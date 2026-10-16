//! Integration tests — permission catalog, grants and token claims against
//! Postgres.  The combined-mode scenario mirrors the in-memory one in
//! `tests/authorization.rs`, so the SQL merge is checked against the same
//! expectations.
//!
//! The catalog is shared by concurrently running tests, so every code carries
//! a per-test tag and no test depends on absolute catalog versions.
//!
//! Run with:
//!   cargo test -p z-auth-postgres --test permissions

mod helpers;

use std::net::{IpAddr, Ipv4Addr};

use uuid::Uuid;
use z_auth::AuthError;
use z_auth::ZAuth;
use z_auth::identity::access::NewRole;
use z_auth::identity::user::RegisterUser;
use z_auth::security::authentication::{ClientContext, Credentials, LoginOutcome, TokenPair};
use z_auth::security::authorization::{NewPermission, PermissionKind, PermissionValue};

use crate::helpers::{cleanup_user_by_id, create_test_user, make_service_in, unique_email};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
const PASSWORD: &str = "Blablabla1!";

fn tag() -> String {
    Uuid::new_v4().simple().to_string()[..10].to_string()
}

/// Permission codes for one test run.
struct Codes {
    view: String,
    export: String,
    region: String,
    upload: String,
}

async fn define_catalog(auth: &ZAuth, t: &str) -> Codes {
    let codes = Codes {
        view: format!("t{t}.reports.view"),
        export: format!("t{t}.reports.export"),
        region: format!("t{t}.region"),
        upload: format!("t{t}.upload.max_mb"),
    };
    let p = auth.permissions();
    let define = |code: &String, kind, options: &[&str]| NewPermission {
        code: code.clone(),
        kind,
        description: Some("integration test".into()),
        options: options.iter().map(|o| (*o).into()).collect(),
    };
    p.define(&define(&codes.view, PermissionKind::Bool, &[]))
        .await
        .unwrap();
    p.define(&define(
        &codes.export,
        PermissionKind::Multi,
        &["csv", "pdf", "xlsx"],
    ))
    .await
    .unwrap();
    p.define(&define(
        &codes.region,
        PermissionKind::Single,
        &["eu", "us"],
    ))
    .await
    .unwrap();
    p.define(&define(
        &codes.upload,
        PermissionKind::Text { max_length: 8 },
        &[],
    ))
    .await
    .unwrap();
    codes
}

async fn drop_catalog(auth: &ZAuth, codes: &Codes) {
    for code in [&codes.view, &codes.export, &codes.region, &codes.upload] {
        auth.permissions().delete(code).await.unwrap();
    }
}

async fn user(auth: &ZAuth) -> (Uuid, String) {
    let email = unique_email("perm");
    let user = create_test_user(
        auth,
        RegisterUser {
            email: email.clone(),
            password: PASSWORD.into(),
            username: None,
            first_name: None,
            last_name: None,
        },
    )
    .await;
    (user.id, email)
}

async fn login(auth: &ZAuth, email: &str) -> TokenPair {
    auth.authentication()
        .login(
            Credentials {
                email: email.into(),
                password: PASSWORD.into(),
            },
            ClientContext::new(IP),
        )
        .await
        .and_then(LoginOutcome::into_tokens)
        .unwrap()
}

#[tokio::test]
async fn test_catalog_round_trips_every_kind_with_permanent_positions() {
    let auth = make_service_in("permissions").await;
    let t = tag();
    let codes = define_catalog(&auth, &t).await;

    // The cache (updated by `define`) matches a fresh load from Postgres.
    let cached = auth.permissions().catalog().unwrap();
    let loaded = auth.permissions().reload_catalog().await.unwrap();
    let ours = |c: &z_auth::security::authorization::PermissionCatalog| {
        let mut v: Vec<_> = c
            .permissions
            .iter()
            .filter(|p| p.code.starts_with(&format!("t{t}.")))
            .cloned()
            .collect();
        v.sort_by(|a, b| a.code.cmp(&b.code));
        v
    };
    assert_eq!(ours(&cached), ours(&loaded));
    let entries = ours(&loaded);
    assert_eq!(entries.len(), 4);
    let export = entries.iter().find(|p| p.code == codes.export).unwrap();
    assert_eq!(export.kind, PermissionKind::Multi);
    assert_eq!(export.options.len(), 3);
    let upload = entries.iter().find(|p| p.code == codes.upload).unwrap();
    assert_eq!(upload.kind, PermissionKind::Text { max_length: 8 });
    assert!(upload.position.is_some());

    // New positions always exceed every earlier one, even after deletes.
    let before = loaded.version;
    auth.permissions().delete(&codes.region).await.unwrap();
    let updated = auth
        .permissions()
        .add_option(&codes.export, "json")
        .await
        .unwrap();
    let json = updated.options.iter().find(|o| o.code == "json").unwrap();
    assert!(u64::from(json.position) > before);

    // Duplicates map to domain errors.
    let dup = auth
        .permissions()
        .define(&NewPermission {
            code: codes.view.clone(),
            kind: PermissionKind::Bool,
            description: None,
            options: vec![],
        })
        .await
        .unwrap_err();
    assert!(
        matches!(dup, AuthError::PermissionAlreadyExists),
        "got {dup:?}"
    );

    for code in [&codes.view, &codes.export, &codes.upload] {
        auth.permissions().delete(code).await.unwrap();
    }
}

#[tokio::test]
async fn test_combined_merge_in_sql_matches_the_documented_rules() {
    let auth = make_service_in("combined").await;
    let t = tag();
    let c = define_catalog(&auth, &t).await;
    let roles = auth.roles();
    // Codes chosen so that `a…` sorts before `m…` (role precedence).
    let analyst = roles
        .create(&NewRole {
            code: format!("a{t}"),
            name: format!("Analyst {t}"),
            description: None,
        })
        .await
        .unwrap();
    let manager = roles
        .create(&NewRole {
            code: format!("m{t}"),
            name: format!("Manager {t}"),
            description: None,
        })
        .await
        .unwrap();

    let p = auth.permissions();
    p.grant_to_role(analyst.id, &c.view, &PermissionValue::Allow)
        .await
        .unwrap();
    p.grant_to_role(
        analyst.id,
        &c.export,
        &PermissionValue::Choices(vec!["csv".into()]),
    )
    .await
    .unwrap();
    p.grant_to_role(analyst.id, &c.region, &PermissionValue::Choice("us".into()))
        .await
        .unwrap();
    p.grant_to_role(analyst.id, &c.upload, &PermissionValue::Text("100".into()))
        .await
        .unwrap();
    p.grant_to_role(
        manager.id,
        &c.export,
        &PermissionValue::Choices(vec!["pdf".into()]),
    )
    .await
    .unwrap();
    p.grant_to_role(manager.id, &c.region, &PermissionValue::Choice("eu".into()))
        .await
        .unwrap();

    let (user_id, email) = user(&auth).await;
    roles.assign(user_id, analyst.id).await.unwrap();
    roles.assign(user_id, manager.id).await.unwrap();
    p.grant_to_user(user_id, &c.upload, &PermissionValue::Text("500".into()))
        .await
        .unwrap();

    let pair = login(&auth, &email).await;
    let claims = auth.verifier().verify(&pair.access_token).unwrap();
    let authz = auth.authorizer();
    assert_eq!(
        authz.roles(&claims),
        [analyst.code.clone(), manager.code.clone()]
    );
    let perms = authz.permissions(&claims);
    assert!(perms.allowed(&c.view), "bool: any role");
    assert_eq!(perms.choices(&c.export), ["csv", "pdf"], "multi: union");
    assert_eq!(
        perms.choice(&c.region),
        Some("us"),
        "single: lowest role code"
    );
    assert_eq!(perms.text(&c.upload), Some("500"), "direct grant wins");

    // A role revoke is picked up by the next refresh.
    roles.revoke(user_id, analyst.id).await.unwrap();
    let next = auth
        .authentication()
        .refresh(
            &pair.access_token,
            &pair.refresh_token,
            ClientContext::new(IP),
        )
        .await
        .unwrap();
    let perms = authz.permissions(&auth.verifier().verify(&next.access_token).unwrap());
    assert!(!perms.allowed(&c.view));
    assert_eq!(perms.choices(&c.export), ["pdf"]);
    assert_eq!(perms.choice(&c.region), Some("eu"));
    assert_eq!(perms.text(&c.upload), Some("500"));

    cleanup_user_by_id(&auth, user_id).await.unwrap();
    roles.delete(analyst.id).await.unwrap();
    roles.delete(manager.id).await.unwrap();
    drop_catalog(&auth, &c).await;
}

#[tokio::test]
async fn test_role_codes_are_unique_and_validated() {
    let auth = make_service_in("rbac").await;
    let t = tag();
    let role = auth
        .roles()
        .create(&NewRole {
            code: format!("r{t}"),
            name: format!("Role {t}"),
            description: None,
        })
        .await
        .unwrap();
    assert_eq!(
        auth.roles()
            .find_by_code(&role.code)
            .await
            .unwrap()
            .map(|r| r.id),
        Some(role.id)
    );
    let dup = auth
        .roles()
        .create(&NewRole {
            code: role.code.clone(),
            name: format!("Other {t}"),
            description: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(dup, AuthError::RoleAlreadyExists), "got {dup:?}");
    auth.roles().delete(role.id).await.unwrap();
}

#[tokio::test]
async fn test_direct_grants_are_listed_per_owner() {
    use z_auth::security::authorization::GrantView;

    let auth = make_service_in("combined").await;
    let t = tag();
    let codes = define_catalog(&auth, &t).await;
    let (user_id, _) = user(&auth).await;
    let role = auth
        .roles()
        .create(&NewRole {
            code: format!("t{t}.lister"),
            name: format!("t{t} lister"),
            description: None,
        })
        .await
        .unwrap();

    let p = auth.permissions();
    p.grant_to_user(
        user_id,
        &codes.export,
        &PermissionValue::Choices(vec!["xlsx".into(), "csv".into()]),
    )
    .await
    .unwrap();
    p.grant_to_user(user_id, &codes.upload, &PermissionValue::Text("50".into()))
        .await
        .unwrap();
    p.grant_to_role(
        role.id,
        &codes.region,
        &PermissionValue::Choice("us".into()),
    )
    .await
    .unwrap();

    assert_eq!(
        p.user_grants(user_id).await.unwrap(),
        [
            GrantView {
                permission_code: codes.export.clone(),
                value: PermissionValue::Choices(vec!["csv".into(), "xlsx".into()]),
            },
            GrantView {
                permission_code: codes.upload.clone(),
                value: PermissionValue::Text("50".into()),
            },
        ]
    );
    assert_eq!(
        p.role_grants(role.id).await.unwrap(),
        [GrantView {
            permission_code: codes.region.clone(),
            value: PermissionValue::Choice("us".into()),
        }]
    );

    cleanup_user_by_id(&auth, user_id).await.unwrap();
    auth.roles().delete(role.id).await.unwrap();
    drop_catalog(&auth, &codes).await;
}
