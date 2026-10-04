//! Role management — against in-memory adapters.
// The facade's defaults need the `argon2` and `crypto` features.
#![cfg(all(feature = "argon2", feature = "crypto"))]

mod support;

use auth_lib::prelude::*;

use crate::support::{make_auth, new_role};

#[tokio::test]
async fn test_create_role_success() {
    let auth = make_auth();
    let role = auth.roles().create(&new_role("admin")).await.unwrap();

    assert_eq!(role.name, "admin");
    assert_eq!(role.description.as_deref(), Some("Description for admin"));
}

#[tokio::test]
async fn test_create_role_no_description() {
    let auth = make_auth();
    let role = auth
        .roles()
        .create(&NewRole {
            code: "guest".into(),
            name: "guest".into(),
            description: None,
        })
        .await
        .unwrap();
    assert!(role.description.is_none());
}

#[tokio::test]
async fn test_find_by_id_and_name() {
    let auth = make_auth();
    let created = auth.roles().create(&new_role("moderator")).await.unwrap();

    let by_id = auth.roles().find_by_id(created.id).await.unwrap();
    let by_name = auth.roles().find_by_name("moderator").await.unwrap();
    assert_eq!(by_id.as_ref(), Some(&created));
    assert_eq!(by_name.as_ref(), Some(&created));
}

#[tokio::test]
async fn test_find_missing_returns_none() {
    let auth = make_auth();
    assert!(
        auth.roles()
            .find_by_id(uuid::Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );
    assert!(auth.roles().find_by_name("nope").await.unwrap().is_none());
}

#[tokio::test]
async fn test_list_is_sorted_by_name() {
    let auth = make_auth();
    auth.roles().create(&new_role("beta")).await.unwrap();
    auth.roles().create(&new_role("alpha")).await.unwrap();

    let names: Vec<String> = auth
        .roles()
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(names, ["alpha", "beta"]);
}

#[tokio::test]
async fn test_delete_role() {
    let auth = make_auth();
    let role = auth.roles().create(&new_role("to_delete")).await.unwrap();

    assert_eq!(auth.roles().delete(role.id).await.unwrap(), Some(role.id));
    assert!(auth.roles().find_by_id(role.id).await.unwrap().is_none());
    assert_eq!(auth.roles().delete(role.id).await.unwrap(), None);
}

#[tokio::test]
async fn test_exists_by_name() {
    let auth = make_auth();
    auth.roles()
        .create(&new_role("exists_check"))
        .await
        .unwrap();

    assert!(auth.roles().exists_by_name("exists_check").await.unwrap());
    assert!(!auth.roles().exists_by_name("absent").await.unwrap());
}

#[tokio::test]
async fn test_create_duplicate_name_fails() {
    let auth = make_auth();
    auth.roles().create(&new_role("unique_role")).await.unwrap();

    let err = auth
        .roles()
        .create(&new_role("unique_role"))
        .await
        .expect_err("duplicate name must fail");
    assert!(matches!(err, AuthError::RoleAlreadyExists), "got: {err:?}");
}
