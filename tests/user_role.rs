//! User → role assignments — against in-memory adapters.
// The facade's default password hasher needs the `argon2` feature.
#![cfg(feature = "argon2")]

mod support;

use auth_lib::prelude::*;

use crate::support::{make_auth, new_role, register_request};

async fn user_and_role(auth: &AuthLib) -> (User, Role) {
    let user = auth
        .users()
        .register(register_request("user@example.com", Some("user")))
        .await
        .unwrap();
    let role = auth.roles().create(&new_role("editor")).await.unwrap();
    (user, role)
}

async fn active_role_ids(auth: &AuthLib, user_id: uuid::Uuid) -> Vec<uuid::Uuid> {
    auth.users()
        .find_with_roles_by_id(user_id)
        .await
        .unwrap()
        .expect("user should exist")
        .roles
        .into_iter()
        .map(|r| r.id)
        .collect()
}

#[tokio::test]
async fn test_new_user_has_no_roles() {
    let auth = make_auth();
    let (user, _) = user_and_role(&auth).await;
    assert!(active_role_ids(&auth, user.id).await.is_empty());
}

#[tokio::test]
async fn test_assign_role_appears_in_user_roles() {
    let auth = make_auth();
    let (user, role) = user_and_role(&auth).await;

    assert!(auth.roles().assign(user.id, role.id).await.unwrap());
    assert_eq!(active_role_ids(&auth, user.id).await, [role.id]);
    assert!(auth.roles().has_role(user.id, role.id).await.unwrap());
}

#[tokio::test]
async fn test_assign_duplicate_active_returns_false() {
    let auth = make_auth();
    let (user, role) = user_and_role(&auth).await;

    assert!(auth.roles().assign(user.id, role.id).await.unwrap());
    assert!(!auth.roles().assign(user.id, role.id).await.unwrap());
}

#[tokio::test]
async fn test_revoke_role() {
    let auth = make_auth();
    let (user, role) = user_and_role(&auth).await;
    auth.roles().assign(user.id, role.id).await.unwrap();

    assert!(auth.roles().revoke(user.id, role.id).await.unwrap());
    assert!(active_role_ids(&auth, user.id).await.is_empty());
    assert!(!auth.roles().has_role(user.id, role.id).await.unwrap());
    // Revoking again (or never-assigned) is not an error.
    assert!(!auth.roles().revoke(user.id, role.id).await.unwrap());
}

#[tokio::test]
async fn test_assignment_history_is_kept() {
    let auth = make_auth();
    let (user, role) = user_and_role(&auth).await;

    auth.roles().assign(user.id, role.id).await.unwrap();
    auth.roles().revoke(user.id, role.id).await.unwrap();
    auth.roles().assign(user.id, role.id).await.unwrap();

    let active = auth.roles().list_user_assignments(user.id).await.unwrap();
    let history = auth
        .roles()
        .list_user_assignment_history(user.id)
        .await
        .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(history.len(), 2);
    assert_eq!(history.iter().filter(|a| a.revoked_at.is_some()).count(), 1);
}

#[tokio::test]
async fn test_revoke_all_for_user() {
    let auth = make_auth();
    let (user, role) = user_and_role(&auth).await;
    let other = auth.roles().create(&new_role("viewer")).await.unwrap();
    auth.roles().assign(user.id, role.id).await.unwrap();
    auth.roles().assign(user.id, other.id).await.unwrap();

    assert_eq!(auth.roles().revoke_all_for_user(user.id).await.unwrap(), 2);
    assert!(active_role_ids(&auth, user.id).await.is_empty());
}

#[tokio::test]
async fn test_role_deletion_removes_assignments() {
    let auth = make_auth();
    let (user, role) = user_and_role(&auth).await;
    auth.roles().assign(user.id, role.id).await.unwrap();

    auth.roles().delete(role.id).await.unwrap();
    assert!(active_role_ids(&auth, user.id).await.is_empty());
}

#[tokio::test]
async fn test_user_deletion_removes_assignments() {
    let auth = make_auth();
    let (user, role) = user_and_role(&auth).await;
    auth.roles().assign(user.id, role.id).await.unwrap();

    auth.users().delete(user.id).await.unwrap();
    assert!(
        auth.users()
            .find_with_roles_by_id(user.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        auth.roles()
            .list_user_assignment_history(user.id)
            .await
            .unwrap()
            .is_empty()
    );
}
