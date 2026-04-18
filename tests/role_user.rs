/// Integration tests — role repository
///
/// These tests talk to a real PostgreSQL database.
/// Set the same env-vars (or `.env`) used by the application:
///
///   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
///
/// Run with:
///   cargo test --test role_user -- --test-threads=1
/// or:
///   cargo test --test role_user
mod helpers;

use auth_lib::model::role::NewRole;

use crate::helpers::{cleanup_role_by_name, make_role_repo, unique_name};

// ── Shared helpers ────────────────────────────────────────────────────────────

// fn init_config() -> &'static Config {
//     if Config::is_initialized() {
//         return Config::global();
//     }

//     Config::init_with(DirectLoader::new(
//         RawConfig::default()
//             .db_backend(DatabaseBackend::Postgres)
//             .db_host("localhost")
//             .db_port(5432)
//             .db_user("postgres")
//             .db_password("passw")
//             .db_name("auth")
//             .db_max_pool_size(20)
//             .db_connect_timeout_secs(10)
//             .jwt_secret("my-very-long-jwt-signing-secret")
//             .jwt_access_expiry_secs(900)
//             .jwt_refresh_expiry_secs(604_800)
//             .jwt_issuer("auth-lib-test"),
//     ))
//     .expect("Failed to load config")
// }

// async fn make_repo() -> Arc<dyn RoleRepo> {
//     let cfg = init_config();
//     build_role_repo(&cfg.database)
//         .await
//         .expect("Failed to build role repo")
// }

// /// Delete a role by name if it exists. Returns the deleted UUID, or None.
// async fn cleanup_role(
//     repo: &Arc<dyn RoleRepo>,
//     name: &str,
// ) -> Result<Option<uuid::Uuid>, AuthError> {
//     if let Some(role) = repo.find_by_name(name).await? {
//         repo.delete(role.id).await?;
//         return Ok(Some(role.id));
//     }
//     Ok(None)
// }

fn new_role(name: &str) -> NewRole {
    NewRole {
        name: name.to_string(),
        description: Some(format!("Description for {name}")),
    }
}

// fn unique_name(base: &str) -> String {
//     format!("{base}_{}", uuid::Uuid::new_v4().simple())
// }

// ── Happy-path tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_role_success() {
    let repo = make_role_repo().await;
    let name = unique_name("admin");

    let role = repo
        .create(new_role(&name))
        .await
        .expect("create should succeed");

    assert!(!role.id.to_string().is_empty());
    assert_eq!(role.name, name);
    assert_eq!(
        role.description.as_deref(),
        Some(format!("Description for {name}").as_str())
    );

    cleanup_role_by_name(&repo, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_create_role_no_description() {
    let repo = make_role_repo().await;
    let name = unique_name("guest");

    let role = repo
        .create(NewRole {
            name: name.clone(),
            description: None,
        })
        .await
        .expect("create with no description should succeed");

    assert_eq!(role.name, name);
    assert!(role.description.is_none());

    cleanup_role_by_name(&repo, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_find_by_id_returns_role() {
    let repo = make_role_repo().await;
    let name = unique_name("moderator");

    let created = repo.create(new_role(&name)).await.expect("create failed");
    let found = repo
        .find_by_id(created.id)
        .await
        .expect("find_by_id failed")
        .expect("role should exist");

    assert_eq!(found.id, created.id);
    assert_eq!(found.name, name);

    cleanup_role_by_name(&repo, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_find_by_id_returns_none_for_missing() {
    let repo = make_role_repo().await;

    let result = repo
        .find_by_id(uuid::Uuid::new_v4())
        .await
        .expect("find_by_id should not error on a missing UUID");

    assert!(result.is_none());
}

#[tokio::test]
async fn test_find_by_name_returns_role() {
    let repo = make_role_repo().await;
    let name = unique_name("editor");

    repo.create(new_role(&name)).await.expect("create failed");

    let found = repo
        .find_by_name(&name)
        .await
        .expect("find_by_name failed")
        .expect("role should exist");

    assert_eq!(found.name, name);

    cleanup_role_by_name(&repo, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_find_by_name_returns_none_for_missing() {
    let repo = make_role_repo().await;

    let result = repo
        .find_by_name(&unique_name("nonexistent"))
        .await
        .expect("find_by_name should not error on a missing name");

    assert!(result.is_none());
}

#[tokio::test]
async fn test_list_all_includes_created_roles() {
    let repo = make_role_repo().await;
    let alpha = unique_name("list_alpha");
    let beta = unique_name("list_beta");

    repo.create(new_role(&alpha))
        .await
        .expect("create alpha failed");
    repo.create(new_role(&beta))
        .await
        .expect("create beta failed");

    let all = repo.list_all().await.expect("list_all failed");
    let names: Vec<&str> = all.iter().map(|r| r.name.as_str()).collect();

    assert!(names.contains(&alpha.as_str()), "alpha should be in list");
    assert!(names.contains(&beta.as_str()), "beta should be in list");

    // Both names share the same base prefix so their UUID suffixes determine
    // sort order — we can't assert relative position, only presence.
    cleanup_role_by_name(&repo, &alpha)
        .await
        .expect("cleanup alpha failed");
    cleanup_role_by_name(&repo, &beta)
        .await
        .expect("cleanup beta failed");
}

#[tokio::test]
async fn test_delete_role_returns_true() {
    let repo = make_role_repo().await;
    let name = unique_name("to_delete");

    let created = repo.create(new_role(&name)).await.expect("create failed");
    let deleted = repo.delete(created.id).await.expect("delete failed");

    assert!(deleted, "delete should return true when a row was removed");

    let after = repo
        .find_by_id(created.id)
        .await
        .expect("find_by_id failed");
    assert!(after.is_none(), "role should not exist after deletion");
}

#[tokio::test]
async fn test_delete_missing_role_returns_false() {
    let repo = make_role_repo().await;

    let deleted = repo
        .delete(uuid::Uuid::new_v4())
        .await
        .expect("delete on missing UUID should not error");

    assert!(!deleted, "delete should return false when no row was found");
}

#[tokio::test]
async fn test_exists_by_name_true_after_create() {
    let repo = make_role_repo().await;
    let name = unique_name("exists_check");

    repo.create(new_role(&name)).await.expect("create failed");

    let exists = repo
        .exists_by_name(&name)
        .await
        .expect("exists_by_name failed");
    assert!(exists);

    cleanup_role_by_name(&repo, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_exists_by_name_false_for_missing() {
    let repo = make_role_repo().await;

    let exists = repo
        .exists_by_name(&unique_name("absent"))
        .await
        .expect("exists_by_name should not error");

    assert!(!exists);
}

#[tokio::test]
async fn test_create_duplicate_name_fails() {
    let repo = make_role_repo().await;
    let name = unique_name("unique_role");

    repo.create(new_role(&name))
        .await
        .expect("First create should succeed");

    let err = repo
        .create(new_role(&name))
        .await
        .expect_err("Second create with the same name must fail");

    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unique")
            || msg.contains("duplicate")
            || msg.contains("already exists")
            || msg.contains("roles_name_key"),
        "Expected a uniqueness violation, got: {err:?}"
    );

    cleanup_role_by_name(&repo, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_db_unique_index_rejects_duplicate_name() {
    let repo = make_role_repo().await;
    let name = unique_name("idx_role");

    let first = NewRole {
        name: name.clone(),
        description: None,
    };
    let second = NewRole {
        name: name.clone(),
        description: Some("duplicate attempt".into()),
    };

    repo.create(first)
        .await
        .expect("First insert should succeed");

    let err = repo
        .create(second)
        .await
        .expect_err("Second insert with the same name must fail at DB level");

    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unique")
            || msg.contains("duplicate")
            || msg.contains("already exists")
            || msg.contains("roles_name_key"),
        "Expected a DB uniqueness violation, got: {err:?}"
    );

    cleanup_role_by_name(&repo, &name)
        .await
        .expect("cleanup failed");
}
