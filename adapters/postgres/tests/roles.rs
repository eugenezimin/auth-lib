//! Integration tests — role repository
//!
//! These tests talk to a real PostgreSQL database.
//! Set the same env-vars (or `.env`) used by the application:
//!
//!   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
//!
//! Run with:
//!   cargo test -p auth-lib-postgres --test role_user -- --test-threads=1
//! or:
//!   cargo test -p auth-lib-postgres --test role_user

mod helpers;

use auth_lib::access::NewRole;

use crate::helpers::{cleanup_role_by_name, make_service, unique_name};

// ── Shared helpers ────────────────────────────────────────────────────────────

fn new_role(name: &str) -> NewRole {
    NewRole {
        name: name.to_string(),
        description: Some(format!("Description for {name}")),
    }
}

// ── Happy-path tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_role_success() {
    let service = make_service().await;
    let name = unique_name("admin");

    let role = service
        .roles()
        .create(&new_role(&name))
        .await
        .expect("create should succeed");

    assert!(!role.id.to_string().is_empty());
    assert_eq!(role.name, name);
    assert_eq!(
        role.description.as_deref(),
        Some(format!("Description for {name}").as_str())
    );

    cleanup_role_by_name(&service, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_create_role_no_description() {
    let service = make_service().await;
    let name = unique_name("guest");

    let role = service
        .roles()
        .create(&NewRole {
            name: name.clone(),
            description: None,
        })
        .await
        .expect("create with no description should succeed");

    assert_eq!(role.name, name);
    assert!(role.description.is_none());

    cleanup_role_by_name(&service, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_find_by_id_returns_role() {
    let service = make_service().await;
    let name = unique_name("moderator");

    let created = service
        .roles()
        .create(&new_role(&name))
        .await
        .expect("create failed");
    let found = service
        .roles()
        .find_by_id(created.id)
        .await
        .expect("find_by_id failed")
        .expect("role should exist");

    assert_eq!(found.id, created.id);
    assert_eq!(found.name, name);

    cleanup_role_by_name(&service, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_find_by_id_returns_none_for_missing() {
    let service = make_service().await;

    let result = service
        .roles()
        .find_by_id(uuid::Uuid::new_v4())
        .await
        .expect("find_by_id should not error on a missing UUID");

    assert!(result.is_none());
}

#[tokio::test]
async fn test_find_by_name_returns_role() {
    let service = make_service().await;
    let name = unique_name("editor");

    service
        .roles()
        .create(&new_role(&name))
        .await
        .expect("create failed");

    let found = service
        .roles()
        .find_by_name(&name)
        .await
        .expect("find_by_name failed")
        .expect("role should exist");

    assert_eq!(found.name, name);

    cleanup_role_by_name(&service, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_find_by_name_returns_none_for_missing() {
    let service = make_service().await;

    let result = service
        .roles()
        .find_by_name(&unique_name("nonexistent"))
        .await
        .expect("find_by_name should not error on a missing name");

    assert!(result.is_none());
}

#[tokio::test]
async fn test_list_all_includes_created_roles() {
    let service = make_service().await;
    let alpha = unique_name("list_alpha");
    let beta = unique_name("list_beta");

    service
        .roles()
        .create(&new_role(&alpha))
        .await
        .expect("create alpha failed");
    service
        .roles()
        .create(&new_role(&beta))
        .await
        .expect("create beta failed");

    let all = service.roles().list().await.expect("list_all failed");
    let names: Vec<&str> = all.iter().map(|r| r.name.as_str()).collect();

    assert!(names.contains(&alpha.as_str()), "alpha should be in list");
    assert!(names.contains(&beta.as_str()), "beta should be in list");

    // Both names share the same base prefix so their UUID suffixes determine
    // sort order — we can't assert relative position, only presence.
    cleanup_role_by_name(&service, &alpha)
        .await
        .expect("cleanup alpha failed");
    cleanup_role_by_name(&service, &beta)
        .await
        .expect("cleanup beta failed");
}

#[tokio::test]
async fn test_delete_role_returns_true() {
    let service = make_service().await;
    let name = unique_name("to_delete");

    let created = service
        .roles()
        .create(&new_role(&name))
        .await
        .expect("create failed");
    let deleted = service
        .roles()
        .delete(created.id)
        .await
        .expect("delete failed");

    assert!(
        deleted.is_some(),
        "delete should return Some(id) when a row was deleted"
    );

    let after = service
        .roles()
        .find_by_id(created.id)
        .await
        .expect("find_by_id failed");
    assert!(after.is_none(), "role should not exist after deletion");
}

#[tokio::test]
async fn test_delete_missing_role_returns_false() {
    let service = make_service().await;

    let deleted = service
        .roles()
        .delete(uuid::Uuid::new_v4())
        .await
        .expect("delete on missing UUID should not error");

    assert!(
        deleted.is_none(),
        "delete should return None when no row was found"
    );
}

#[tokio::test]
async fn test_exists_by_name_true_after_create() {
    let service = make_service().await;
    let name = unique_name("exists_check");

    service
        .roles()
        .create(&new_role(&name))
        .await
        .expect("create failed");

    let exists = service
        .roles()
        .exists_by_name(&name)
        .await
        .expect("exists_role_by_name failed");
    assert!(exists);

    cleanup_role_by_name(&service, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_exists_by_name_false_for_missing() {
    let service = make_service().await;

    let exists = service
        .roles()
        .exists_by_name(&unique_name("absent"))
        .await
        .expect("exists_role_by_name should not error");

    assert!(!exists);
}

#[tokio::test]
async fn test_create_duplicate_name_fails() {
    let service = make_service().await;
    let name = unique_name("unique_role");

    service
        .roles()
        .create(&new_role(&name))
        .await
        .expect("First create should succeed");

    let err = service
        .roles()
        .create(&new_role(&name))
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

    cleanup_role_by_name(&service, &name)
        .await
        .expect("cleanup failed");
}

#[tokio::test]
async fn test_db_unique_index_rejects_duplicate_name() {
    let service = make_service().await;
    let name = unique_name("idx_role");

    let first = NewRole {
        name: name.clone(),
        description: None,
    };
    let second = NewRole {
        name: name.clone(),
        description: Some("duplicate attempt".into()),
    };

    service
        .roles()
        .create(&first)
        .await
        .expect("First insert should succeed");

    let err = service
        .roles()
        .create(&second)
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

    cleanup_role_by_name(&service, &name)
        .await
        .expect("cleanup failed");
}
