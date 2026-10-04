//! Authorization in the token — rbac / permissions / combined / none modes,
//! against in-memory adapters.
//!
//! Invariants checked here:
//! - authorization data is read from the store only at login / refresh;
//!   verification and authorizer checks make **no** repository calls;
//! - changes become visible at the next refresh;
//! - the catalog never travels in a token (only its version, `pv`).

// The facade's defaults need the `argon2` and `crypto` features.
#![cfg(all(feature = "argon2", feature = "crypto"))]

mod support;

use std::sync::Arc;

use auth_lib::prelude::*;

use crate::support::{
    IP_A, InMemoryDb, MockClock, credentials, ctx, raw_config, register_and_login, server,
    server_with,
};

fn config(mode: &str) -> AuthConfig {
    raw_config().authz_mode(mode).build().unwrap()
}

fn claims(s: &support::Server, pair: &TokenPair) -> Claims {
    s.auth.verifier().verify(&pair.access_token).unwrap()
}

async fn refresh(s: &support::Server, pair: &TokenPair) -> TokenPair {
    s.auth
        .authentication()
        .refresh(&pair.access_token, &pair.refresh_token, ctx(IP_A))
        .await
        .unwrap()
}

async fn role(s: &support::Server, code: &str) -> Role {
    s.auth
        .roles()
        .create(&NewRole {
            code: code.into(),
            name: code.to_uppercase(),
            description: None,
        })
        .await
        .unwrap()
}

/// reports.view (bool), reports.export (multi), region (single), upload.max_mb (text).
async fn demo_catalog(s: &support::Server) {
    let p = s.auth.permissions();
    for new in [
        NewPermission {
            code: "reports.view".into(),
            kind: PermissionKind::Bool,
            description: None,
            options: vec![],
        },
        NewPermission {
            code: "reports.export".into(),
            kind: PermissionKind::Multi,
            description: None,
            options: vec!["csv".into(), "pdf".into(), "xlsx".into()],
        },
        NewPermission {
            code: "region".into(),
            kind: PermissionKind::Single,
            description: None,
            options: vec!["eu".into(), "us".into()],
        },
        NewPermission {
            code: "upload.max_mb".into(),
            kind: PermissionKind::Text { max_length: 8 },
            description: None,
            options: vec![],
        },
    ] {
        p.define(&new).await.unwrap();
    }
}

// ── rbac (default) ────────────────────────────────────────────────────────────

#[tokio::test]
async fn rbac_tokens_carry_role_codes_and_pick_up_changes_on_refresh() {
    let s = server(raw_config().build().unwrap()); // default mode = rbac
    let admin = role(&s, "admin").await;
    let user_role = role(&s, "user").await;
    let (user, _) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.auth.roles().assign(user.id, admin.id).await.unwrap();
    s.auth.roles().assign(user.id, user_role.id).await.unwrap();

    let pair = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap();
    let c = claims(&s, &pair);
    let authz = s.auth.authorizer();
    assert_eq!(authz.roles(&c), ["admin", "user"], "sorted role codes");
    assert!(authz.has_role(&c, "admin"));
    assert!(
        c.authz.as_ref().unwrap().permissions.is_none(),
        "rbac: no prm/pv"
    );

    // Revoking doesn't touch the current token…
    s.auth.roles().revoke(user.id, admin.id).await.unwrap();
    assert!(authz.has_role(&claims(&s, &pair), "admin"));
    // …the next refresh does.
    let next = refresh(&s, &pair).await;
    assert_eq!(authz.roles(&claims(&s, &next)), ["user"]);

    // Permission APIs are off in rbac.
    assert!(matches!(
        s.auth.permissions().catalog(),
        Err(AuthError::AuthzModeDisabled(_))
    ));
}

#[tokio::test]
async fn role_codes_are_validated() {
    let s = server(config("rbac"));
    let err = s
        .auth
        .roles()
        .create(&NewRole {
            code: "Not Valid".into(),
            name: "x".into(),
            description: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidCode(_)), "got {err:?}");
}

// ── verification never touches the store ──────────────────────────────────────

#[tokio::test]
async fn verification_and_checks_make_no_repository_calls() {
    let s = server(config("combined"));
    demo_catalog(&s).await;
    let (user, _) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.auth
        .permissions()
        .grant_to_user(user.id, "reports.view", &PermissionValue::Allow)
        .await
        .unwrap();
    let pair = refresh(
        &s,
        &s.auth
            .authentication()
            .login(credentials("a@example.com"), ctx(IP_A))
            .await
            .unwrap(),
    )
    .await;

    let before = s.db.calls();
    for _ in 0..100 {
        let c = s.auth.verifier().verify(&pair.access_token).unwrap();
        assert!(s.auth.authorizer().permissions(&c).allowed("reports.view"));
        assert!(!s.auth.authorizer().has_role(&c, "admin"));
        s.auth.permissions().catalog().unwrap();
    }
    assert_eq!(
        s.db.calls(),
        before,
        "no store access outside login / refresh"
    );
}

// ── permissions ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn permission_tokens_decode_with_the_catalog() {
    let s = server(config("permissions"));
    demo_catalog(&s).await;
    let (user, _) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    let p = s.auth.permissions();
    p.grant_to_user(user.id, "reports.view", &PermissionValue::Allow)
        .await
        .unwrap();
    p.grant_to_user(
        user.id,
        "reports.export",
        &PermissionValue::Choices(vec!["pdf".into(), "csv".into()]),
    )
    .await
    .unwrap();
    p.grant_to_user(user.id, "region", &PermissionValue::Choice("us".into()))
        .await
        .unwrap();
    p.grant_to_user(
        user.id,
        "upload.max_mb",
        &PermissionValue::Text("250".into()),
    )
    .await
    .unwrap();

    let pair = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap();
    let c = claims(&s, &pair);
    let encoded = c.authz.as_ref().unwrap().permissions.as_ref().unwrap();
    assert_eq!(encoded.catalog_version, p.catalog().unwrap().version);
    assert!(
        c.authz.as_ref().unwrap().roles.is_empty(),
        "permissions mode: no rol"
    );

    let perms = s.auth.authorizer().permissions(&c);
    assert!(perms.allowed("reports.view"));
    assert_eq!(perms.choices("reports.export"), ["csv", "pdf"]);
    assert_eq!(perms.choice("region"), Some("us"));
    assert_eq!(perms.text("upload.max_mb"), Some("250"));
    assert!(!perms.catalog_outdated);

    // Revoke → visible after refresh only.
    p.revoke_from_user(user.id, "reports.view").await.unwrap();
    assert!(s.auth.authorizer().permissions(&c).allowed("reports.view"));
    let next = refresh(&s, &pair).await;
    assert!(
        !s.auth
            .authorizer()
            .permissions(&claims(&s, &next))
            .allowed("reports.view")
    );

    // Values must fit their kind; roles are off.
    assert!(matches!(
        p.grant_to_user(user.id, "region", &PermissionValue::Allow)
            .await,
        Err(AuthError::InvalidPermissionValue(_))
    ));
    assert!(matches!(
        p.grant_to_user(user.id, "nope", &PermissionValue::Allow)
            .await,
        Err(AuthError::PermissionNotFound)
    ));
    assert!(matches!(
        s.auth.roles().list().await,
        Err(AuthError::AuthzModeDisabled(_))
    ));
}

#[tokio::test]
async fn catalog_positions_are_permanent() {
    let s = server(config("permissions"));
    demo_catalog(&s).await;
    let p = s.auth.permissions();
    let v1 = p.catalog().unwrap().version;
    p.delete("region").await.unwrap();
    let after_add = p.add_option("reports.export", "json").await.unwrap();
    let json = after_add.options.iter().find(|o| o.code == "json").unwrap();
    assert!(
        u64::from(json.position) > v1,
        "new positions never reuse old ones"
    );
    assert!(p.catalog().unwrap().version > v1);
    assert!(
        p.catalog()
            .unwrap()
            .permissions
            .iter()
            .all(|x| x.code != "region")
    );
}

#[tokio::test]
async fn login_refreshes_a_stale_catalog_cache_and_verify_only_instances_fail_closed() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock.clone()));
    let cfg = config("permissions");
    let admin = server_with(db.clone(), clock.clone(), cfg.clone());
    let issuer = server_with(db.clone(), clock.clone(), cfg.clone());
    let verify_only = server_with(db, clock, cfg);

    demo_catalog(&admin).await; // only `admin`'s cache knows the catalog
    let (user, _) = register_and_login(&issuer.auth, "a@example.com", IP_A).await;
    admin
        .auth
        .permissions()
        .grant_to_user(user.id, "reports.view", &PermissionValue::Allow)
        .await
        .unwrap();

    // Logging in on `issuer` sees a newer catalog version and reloads its cache.
    let pair = issuer
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap();
    let c = claims(&issuer, &pair);
    assert!(
        issuer
            .auth
            .authorizer()
            .permissions(&c)
            .allowed("reports.view")
    );

    // An instance that never logged anyone in still has an empty cache:
    // nothing is granted, and it can tell its catalog is outdated.
    let perms = verify_only.auth.authorizer().permissions(&c);
    assert!(!perms.allowed("reports.view"));
    assert!(perms.catalog_outdated);
    // Startup bootstrap fixes that.
    verify_only
        .auth
        .permissions()
        .reload_catalog()
        .await
        .unwrap();
    assert!(
        verify_only
            .auth
            .authorizer()
            .permissions(&c)
            .allowed("reports.view")
    );
}

// ── combined ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn combined_merges_role_and_direct_grants() {
    let s = server(config("combined"));
    demo_catalog(&s).await;
    let analyst = role(&s, "analyst").await;
    let manager = role(&s, "manager").await;
    let p = s.auth.permissions();
    // analyst: view, export csv, region us, upload 100
    p.grant_to_role(analyst.id, "reports.view", &PermissionValue::Allow)
        .await
        .unwrap();
    p.grant_to_role(
        analyst.id,
        "reports.export",
        &PermissionValue::Choices(vec!["csv".into()]),
    )
    .await
    .unwrap();
    p.grant_to_role(analyst.id, "region", &PermissionValue::Choice("us".into()))
        .await
        .unwrap();
    p.grant_to_role(
        analyst.id,
        "upload.max_mb",
        &PermissionValue::Text("100".into()),
    )
    .await
    .unwrap();
    // manager: export pdf, region eu
    p.grant_to_role(
        manager.id,
        "reports.export",
        &PermissionValue::Choices(vec!["pdf".into()]),
    )
    .await
    .unwrap();
    p.grant_to_role(manager.id, "region", &PermissionValue::Choice("eu".into()))
        .await
        .unwrap();

    let (user, _) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    s.auth.roles().assign(user.id, analyst.id).await.unwrap();
    s.auth.roles().assign(user.id, manager.id).await.unwrap();
    // direct override of the text value
    p.grant_to_user(
        user.id,
        "upload.max_mb",
        &PermissionValue::Text("500".into()),
    )
    .await
    .unwrap();

    let pair = s
        .auth
        .authentication()
        .login(credentials("a@example.com"), ctx(IP_A))
        .await
        .unwrap();
    let c = claims(&s, &pair);
    let authz = s.auth.authorizer();
    assert_eq!(authz.roles(&c), ["analyst", "manager"]);
    let perms = authz.permissions(&c);
    assert!(perms.allowed("reports.view"), "bool: any role");
    assert_eq!(
        perms.choices("reports.export"),
        ["csv", "pdf"],
        "multi: union"
    );
    assert_eq!(
        perms.choice("region"),
        Some("us"),
        "single: lowest role code (analyst)"
    );
    assert_eq!(
        perms.text("upload.max_mb"),
        Some("500"),
        "direct grant wins"
    );

    // Revoking a role removes its grants at the next refresh.
    s.auth.roles().revoke(user.id, analyst.id).await.unwrap();
    let perms = authz.permissions(&claims(&s, &refresh(&s, &pair).await));
    assert!(!perms.allowed("reports.view"));
    assert_eq!(perms.choices("reports.export"), ["pdf"]);
    assert_eq!(perms.choice("region"), Some("eu"));
}

#[tokio::test]
async fn role_grants_need_combined_mode() {
    let s = server(config("permissions"));
    demo_catalog(&s).await;
    let err = s
        .auth
        .permissions()
        .grant_to_role(
            uuid::Uuid::new_v4(),
            "reports.view",
            &PermissionValue::Allow,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, AuthError::AuthzModeDisabled(_)),
        "got {err:?}"
    );
}

// ── none ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn none_mode_issues_identity_only_tokens() {
    let s = server(config("none"));
    let (_, pair) = register_and_login(&s.auth, "a@example.com", IP_A).await;
    assert!(claims(&s, &pair).authz.is_none());
    assert!(matches!(
        s.auth.roles().list().await,
        Err(AuthError::AuthzModeDisabled(_))
    ));
    assert!(matches!(
        s.auth.permissions().catalog(),
        Err(AuthError::AuthzModeDisabled(_))
    ));
}

// ── wiring ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn permission_modes_require_a_permission_repository() {
    let clock = MockClock::new();
    let db = Arc::new(InMemoryDb::new(clock));
    let err = AuthLib::builder(config("combined"), support::repositories(&db))
        .build()
        .err()
        .expect("must fail without .permissions(...)");
    assert!(matches!(err, AuthError::Config(_)), "got {err:?}");
}

#[test]
fn unknown_mode_is_a_config_error() {
    assert!(raw_config().authz_mode("everything").build().is_err());
}
