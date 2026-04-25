/// Integration tests — user-role assignments
///
/// These tests talk to a real PostgreSQL database.
/// Set the same env-vars (or `.env`) used by the application:
///
///   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
///
/// Run with:
///   cargo test --test user_role -- --test-threads=1
///
/// `--test-threads=1` keeps tests sequential so shared DB state
/// (users, roles) doesn't produce races between concurrent tests.
///
/// Each test follows the pattern:
///   create prerequisites → act → assert → cleanup
///
/// Cleanup always runs against IDs captured before the test body, so
/// the suite is fully re-runnable without manual DB resets.
mod helpers;

use auth_lib::{
    model::{role::NewRole, user::RegisterRequest},
    utils::errors::AuthError,
};

use crate::helpers::{
    cleanup_role_by_id, cleanup_user_by_id, create_test_role, create_test_user, make_service,
    unique_email, unique_name,
};

fn test_user_request() -> RegisterRequest {
    RegisterRequest {
        email: unique_email("test_user"),
        password: "Blablabla1!".into(),
        username: Some(unique_name("test_user")),
        first_name: Some("Test".into()),
        last_name: Some("User".into()),
    }
}

fn test_role() -> NewRole {
    NewRole {
        name: unique_name("test_role"),
        description: Some("Created by test helper".into()),
    }
}
// ── Happy-path tests ──────────────────────────────────────────────────────────

/// Assigning a role to a user returns true on success.
#[tokio::test]
async fn test_assign_role_success() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;
    let role = create_test_role(&service, &test_role()).await;

    let assigned = service
        .assign_role(user.user_id, role.id)
        .await
        .expect("assign_role should succeed");

    assert!(assigned, "assign_role should return true on success");

    // Role deletion cascades to users_roles via ON DELETE CASCADE.
    cleanup_role_by_id(&service, role.id)
        .await
        .expect("role cleanup failed");
    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user cleanup failed");
}

/// After assigning, the role appears in find_user_with_roles_by_id.
#[tokio::test]
async fn test_assigned_role_appears_in_user_roles() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;
    let role = create_test_role(&service, &test_role()).await;

    service
        .assign_role(user.user_id, role.id)
        .await
        .expect("assign_role failed");

    let user_with_roles = service
        .find_user_with_roles_by_id(user.user_id)
        .await
        .expect("find_user_with_roles_by_id errored")
        .expect("user should exist");

    assert!(
        user_with_roles
            .roles
            .unwrap_or_default()
            .iter()
            .any(|r| r.id == role.id),
        "assigned role must appear in user's active roles"
    );

    cleanup_role_by_id(&service, role.id)
        .await
        .expect("role cleanup failed");
    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user cleanup failed");
}

/// Revoking an active assignment returns true.
#[tokio::test]
async fn test_revoke_role_success() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;
    let role = create_test_role(&service, &test_role()).await;

    service
        .assign_role(user.user_id, role.id)
        .await
        .expect("assign_role failed");

    let revoked = service
        .revoke_role(user.user_id, role.id)
        .await
        .expect("revoke_role should not error");

    assert!(
        revoked,
        "revoke_role should return true when a row was updated"
    );

    cleanup_role_by_id(&service, role.id)
        .await
        .expect("role cleanup failed");
    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user cleanup failed");
}

/// After revoking, the role no longer appears in find_user_with_roles_by_id.
#[tokio::test]
async fn test_revoked_role_absent_from_user_roles() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;
    let role = create_test_role(&service, &test_role()).await;

    service
        .assign_role(user.user_id, role.id)
        .await
        .expect("assign_role failed");

    service
        .revoke_role(user.user_id, role.id)
        .await
        .expect("revoke_role failed");

    let user_with_roles = service
        .find_user_with_roles_by_id(user.user_id)
        .await
        .expect("find_user_with_roles_by_id errored")
        .expect("user should exist");

    assert!(
        !user_with_roles
            .roles
            .unwrap_or_default()
            .iter()
            .any(|r| r.id == role.id),
        "revoked role must not appear in user's active roles"
    );

    cleanup_role_by_id(&service, role.id)
        .await
        .expect("role cleanup failed");
    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user cleanup failed");
}

/// A newly created user has no active roles.
#[tokio::test]
async fn test_new_user_has_no_roles() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;

    let user_with_roles = service
        .find_user_with_roles_by_id(user.user_id)
        .await
        .expect("find_user_with_roles_by_id errored")
        .expect("user should exist");

    assert!(
        user_with_roles.roles.unwrap_or_default().is_empty(),
        "a brand-new user must have no roles"
    );

    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user cleanup failed");
}

// ── Constraint / error-path tests ─────────────────────────────────────────────

/// Assigning the same role twice (without revoking) must fail with
/// AuthError::RoleAlreadyAssigned — the partial unique index fires.
#[tokio::test]
async fn test_assign_duplicate_active_fails() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;
    let role = create_test_role(&service, &test_role()).await;

    service
        .assign_role(user.user_id, role.id)
        .await
        .expect("first assign_role must succeed");

    let second = service
        .assign_role(user.user_id, role.id)
        .await
        .expect("second assign of the same active role must fail");

    assert!(matches!(second, false), "expected false, got: {second:?}");

    cleanup_role_by_id(&service, role.id)
        .await
        .expect("role cleanup failed");
    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user cleanup failed");
}

/// Revoking a role the user does not hold returns false — not an error.
#[tokio::test]
async fn test_revoke_unassigned_role_returns_false() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;
    let role = create_test_role(&service, &test_role()).await;

    let result = service
        .revoke_role(user.user_id, role.id)
        .await
        .expect("revoke_role on missing assignment must not error");

    assert!(!result, "expected false when no active assignment exists");

    cleanup_role_by_id(&service, role.id)
        .await
        .expect("role cleanup failed");
    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user cleanup failed");
}

/// Revoking an already-revoked assignment returns false.
#[tokio::test]
async fn test_revoke_already_revoked_returns_false() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;
    let role = create_test_role(&service, &test_role()).await;

    service
        .assign_role(user.user_id, role.id)
        .await
        .expect("assign_role failed");

    service
        .revoke_role(user.user_id, role.id)
        .await
        .expect("first revoke_role failed");

    let second = service
        .revoke_role(user.user_id, role.id)
        .await
        .expect("second revoke_role must not error");

    assert!(
        !second,
        "revoking an already-revoked assignment must return false"
    );

    cleanup_role_by_id(&service, role.id)
        .await
        .expect("role cleanup failed");
    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user cleanup failed");
}

// ── Cascade / isolation tests ─────────────────────────────────────────────────

/// Deleting a user cascades to users_roles — the user (and its assignments)
/// disappear without a foreign-key violation.
#[tokio::test]
async fn test_user_deletion_cascades_to_assignments() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;
    let role = create_test_role(&service, &test_role()).await;

    service
        .assign_role(user.user_id, role.id)
        .await
        .expect("assign_role failed");

    // Delete the user — must not fail with a FK violation.
    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user deletion should succeed even with assignments present");

    // The user is gone; querying by ID should return None.
    let gone = service
        .find_user_with_roles_by_id(user.user_id)
        .await
        .expect("find_user_with_roles_by_id must not error after cascade");

    assert!(gone.is_none(), "user must be gone after deletion");

    cleanup_role_by_id(&service, role.id)
        .await
        .expect("role cleanup failed");
}

/// Deleting a role cascades to users_roles — the assignment disappears and
/// the user still exists with an empty role list.
#[tokio::test]
async fn test_role_deletion_cascades_to_assignments() {
    let service = make_service().await;
    let user = create_test_user(&service, test_user_request()).await;
    let role = create_test_role(&service, &test_role()).await;

    service
        .assign_role(user.user_id, role.id)
        .await
        .expect("assign_role failed");

    // Delete the role — cascade must remove the assignment row.
    cleanup_role_by_id(&service, role.id)
        .await
        .expect("role deletion should succeed even with active assignments");

    // The user still exists but now holds no roles.
    let user_with_roles = service
        .find_user_with_roles_by_id(user.user_id)
        .await
        .expect("find_user_with_roles_by_id must not error after role cascade")
        .expect("user must still exist after role deletion");

    assert!(
        user_with_roles.roles.unwrap_or_default().is_empty(),
        "user must have no roles after the assigned role was deleted"
    );

    cleanup_user_by_id(&service, user.user_id)
        .await
        .expect("user cleanup failed");
}
