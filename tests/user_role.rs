// /// Integration tests — user-role repository
// ///
// /// These tests talk to a real PostgreSQL database.
// /// Set the same env-vars (or `.env`) used by the application:
// ///
// ///   DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
// ///
// /// Run with:
// ///   cargo test --test user_role -- --test-threads=1
// ///
// /// `--test-threads=1` keeps tests sequential so shared DB state
// /// (users, roles) doesn't produce races between concurrent tests.
// ///
// /// Each test follows the pattern:
// ///   create prerequisites → act → assert → cleanup
// ///
// /// Cleanup always runs against IDs captured before the test body, so
// /// the suite is fully re-runnable without manual DB resets.
// mod helpers;

// use auth_lib::utils::errors::AuthError;

// use crate::helpers::{
//     cleanup_role_by_id, cleanup_user_by_id, create_test_role, create_test_user, make_service,
// };

// // ── Happy-path tests ──────────────────────────────────────────────────────────

// /// Assigning a role to a user returns a hydrated UserRole with the correct
// /// user_id and role_id, and revoked_at starts as None.
// #[tokio::test]
// async fn test_assign_role_success() {
//     let service = make_service().await;

//     let user = create_test_user(&service).await;
//     let role = create_test_role(&service).await;

//     let assignment = service
//         .assign_role(user.user_id, role.id)
//         .await
//         .expect("assign should succeed");

//     assert!(assignment, "assign should return a True value on success");

//     // Cleanup — role deletion cascades to users_roles via ON DELETE CASCADE.
//     cleanup_role_by_id(&service, role.id)
//         .await
//         .expect("role cleanup failed");
//     cleanup_user_by_id(&service, user.user_id)
//         .await
//         .expect("user cleanup failed");
// }

// /// After assigning, is_role_active returns true.
// #[tokio::test]
// async fn test_is_role_active_true_after_assign() {
//     let service = make_service().await;
//     let user = create_test_user(&service).await;
//     let role = create_test_role(&service).await;

//     service
//         .assign_role(user.user_id, role.id)
//         .await
//         .expect("assign failed");

//     let user_with_roles = service
//         .find_user_with_roles_by_id(user.user_id)
//         .await
//         .unwrap()
//         .expect("find_user_with_roles_by_id failed");

//     assert!(
//         user_with_roles.roles.iter().any(|r| r.id == role.id),
//         "assigned role must appear in user's roles"
//     );

//     cleanup_role_by_id(&service, role.id)
//         .await
//         .expect("role cleanup failed");
//     cleanup_user_by_id(&service, user.user_id)
//         .await
//         .expect("user cleanup failed");
// }

// /// Revoking an active assignment returns true and stamps revoked_at.
// /// Subsequent is_role_active returns false.
// #[tokio::test]
// async fn test_revoke_role_success() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let role = create_test_role(&role_repo).await;

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: role.id,
//         })
//         .await
//         .expect("assign failed");

//     let revoked = user_role_repo
//         .revoke(user.id, role.id)
//         .await
//         .expect("revoke failed");

//     assert!(revoked, "revoke should return true when a row was updated");

//     let still_active = user_role_repo
//         .is_role_active(user.id, role.id)
//         .await
//         .expect("is_role_active failed");

//     assert!(!still_active, "role should not be active after revocation");

//     cleanup_role_by_id(&role_repo, role.id)
//         .await
//         .expect("role cleanup failed");
//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// list_active_for_user returns only active assignments; revoked rows are excluded.
// #[tokio::test]
// async fn test_list_active_excludes_revoked() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let active_role = create_test_role(&role_repo).await;
//     let revoked_role = create_test_role(&role_repo).await;

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: active_role.id,
//         })
//         .await
//         .expect("assign active_role failed");

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: revoked_role.id,
//         })
//         .await
//         .expect("assign revoked_role failed");

//     user_role_repo
//         .revoke(user.id, revoked_role.id)
//         .await
//         .expect("revoke failed");

//     let active_list = user_role_repo
//         .list_active_for_user(user.id)
//         .await
//         .expect("list_active_for_user failed");

//     let role_ids: Vec<uuid::Uuid> = active_list.iter().map(|ur| ur.role_id).collect();

//     assert!(
//         role_ids.contains(&active_role.id),
//         "active role must appear in list"
//     );
//     assert!(
//         !role_ids.contains(&revoked_role.id),
//         "revoked role must not appear in active list"
//     );
//     assert!(
//         active_list.iter().all(|ur| ur.revoked_at.is_none()),
//         "every row returned by list_active must have revoked_at = NULL"
//     );

//     cleanup_role_by_id(&role_repo, active_role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_role_by_id(&role_repo, revoked_role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// list_all_for_user returns both active and revoked assignments.
// #[tokio::test]
// async fn test_list_all_includes_revoked() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let active_role = create_test_role(&role_repo).await;
//     let revoked_role = create_test_role(&role_repo).await;

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: active_role.id,
//         })
//         .await
//         .expect("assign active_role failed");

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: revoked_role.id,
//         })
//         .await
//         .expect("assign revoked_role failed");

//     user_role_repo
//         .revoke(user.id, revoked_role.id)
//         .await
//         .expect("revoke failed");

//     let all = user_role_repo
//         .list_all_for_user(user.id)
//         .await
//         .expect("list_all_for_user failed");

//     let role_ids: Vec<uuid::Uuid> = all.iter().map(|ur| ur.role_id).collect();

//     assert!(
//         role_ids.contains(&active_role.id),
//         "active role must appear"
//     );
//     assert!(
//         role_ids.contains(&revoked_role.id),
//         "revoked role must appear in full history"
//     );

//     // The revoked row must have revoked_at set.
//     let revoked_row = all
//         .iter()
//         .find(|ur| ur.role_id == revoked_role.id)
//         .expect("revoked row must exist");
//     assert!(
//         revoked_row.revoked_at.is_some(),
//         "revoked row must have revoked_at stamped"
//     );

//     cleanup_role_by_id(&role_repo, active_role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_role_by_id(&role_repo, revoked_role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// A role can be re-assigned to a user after it has been revoked.
// /// The partial unique index only blocks duplicate *active* assignments.
// #[tokio::test]
// async fn test_reassign_after_revoke_succeeds() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let role = create_test_role(&role_repo).await;

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: role.id,
//         })
//         .await
//         .expect("first assign failed");

//     user_role_repo
//         .revoke(user.id, role.id)
//         .await
//         .expect("revoke failed");

//     // Re-assigning after revocation must succeed — the partial index only
//     // prevents duplicate *active* pairs.
//     let second = user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: role.id,
//         })
//         .await
//         .expect("re-assign after revoke should succeed");

//     assert!(
//         second.revoked_at.is_none(),
//         "re-assigned row must be active"
//     );

//     // list_all must show two rows for the same (user, role) pair.
//     let all = user_role_repo
//         .list_all_for_user(user.id)
//         .await
//         .expect("list_all_for_user failed");
//     let matching: Vec<_> = all.iter().filter(|ur| ur.role_id == role.id).collect();
//     assert_eq!(
//         matching.len(),
//         2,
//         "history must contain both assignment rows"
//     );

//     cleanup_role_by_id(&role_repo, role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// revoke_all_for_user revokes every active assignment and returns the count.
// #[tokio::test]
// async fn test_revoke_all_for_user() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let role1 = create_test_role(&role_repo).await;
//     let role2 = create_test_role(&role_repo).await;
//     let role3 = create_test_role(&role_repo).await;

//     for role in [&role1, &role2, &role3] {
//         user_role_repo
//             .assign(NewUserRole {
//                 user_id: user.id,
//                 role_id: role.id,
//             })
//             .await
//             .expect("assign failed");
//     }

//     let revoked_count = user_role_repo
//         .revoke_all_for_user(user.id)
//         .await
//         .expect("revoke_all_for_user failed");

//     assert_eq!(
//         revoked_count, 3,
//         "all three active assignments must be revoked"
//     );

//     let still_active = user_role_repo
//         .list_active_for_user(user.id)
//         .await
//         .expect("list_active_for_user failed");

//     assert!(
//         still_active.is_empty(),
//         "no active assignments should remain after revoke_all"
//     );

//     cleanup_role_by_id(&role_repo, role1.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_role_by_id(&role_repo, role2.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_role_by_id(&role_repo, role3.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// A user with no assignments gets an empty list — not an error.
// #[tokio::test]
// async fn test_list_active_empty_for_new_user() {
//     let user_repo = make_user_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;

//     let active = user_role_repo
//         .list_active_for_user(user.id)
//         .await
//         .expect("list_active_for_user failed");

//     assert!(active.is_empty());

//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// // ── Constraint / error-path tests ─────────────────────────────────────────────

// /// Assigning the same role twice (without revoking) must fail with
// /// AuthError::RoleAlreadyAssigned — the partial unique index fires.
// #[tokio::test]
// async fn test_assign_duplicate_active_fails() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let role = create_test_role(&role_repo).await;

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: role.id,
//         })
//         .await
//         .expect("first assign must succeed");

//     let err = user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: role.id,
//         })
//         .await
//         .expect_err("second assign of the same active role must fail");

//     assert!(
//         matches!(err, AuthError::RoleAlreadyAssigned),
//         "expected RoleAlreadyAssigned, got: {err:?}"
//     );

//     cleanup_role_by_id(&role_repo, role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// Revoking a role the user does not hold returns false — not an error.
// #[tokio::test]
// async fn test_revoke_non_existent_assignment_returns_false() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let role = create_test_role(&role_repo).await;

//     let result = user_role_repo
//         .revoke(user.id, role.id)
//         .await
//         .expect("revoke on missing assignment should not error");

//     assert!(!result, "expected false when no active assignment exists");

//     cleanup_role_by_id(&role_repo, role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// Revoking an already-revoked assignment returns false — only the active row
// /// is matched by the WHERE clause.
// #[tokio::test]
// async fn test_revoke_already_revoked_returns_false() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let role = create_test_role(&role_repo).await;

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id: role.id,
//         })
//         .await
//         .expect("assign failed");

//     user_role_repo
//         .revoke(user.id, role.id)
//         .await
//         .expect("first revoke failed");

//     let second_revoke = user_role_repo
//         .revoke(user.id, role.id)
//         .await
//         .expect("second revoke should not error");

//     assert!(
//         !second_revoke,
//         "revoking an already-revoked assignment must return false"
//     );

//     cleanup_role_by_id(&role_repo, role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// is_role_active returns false for a role the user has never held.
// #[tokio::test]
// async fn test_is_role_active_false_for_unassigned() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let role = create_test_role(&role_repo).await;

//     let active = user_role_repo
//         .is_role_active(user.id, role.id)
//         .await
//         .expect("is_role_active failed");

//     assert!(!active);

//     cleanup_role_by_id(&role_repo, role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// revoke_all_for_user on a user with no active assignments returns 0.
// #[tokio::test]
// async fn test_revoke_all_returns_zero_when_none_active() {
//     let user_repo = make_user_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;

//     let count = user_role_repo
//         .revoke_all_for_user(user.id)
//         .await
//         .expect("revoke_all_for_user failed");

//     assert_eq!(count, 0);

//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// // ── Cascade / isolation tests ─────────────────────────────────────────────────

// /// Deleting a user cascades to users_roles — the assignments disappear
// /// without a foreign-key violation.
// #[tokio::test]
// async fn test_user_deletion_cascades_to_assignments() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let role = create_test_role(&role_repo).await;
//     let user_id = user.id; // capture before move

//     user_role_repo
//         .assign(NewUserRole {
//             user_id,
//             role_id: role.id,
//         })
//         .await
//         .expect("assign failed");

//     // Delete the user — must not fail with a FK violation.
//     cleanup_user_by_id(&user_repo, user_id)
//         .await
//         .expect("user deletion should succeed even with assignments present");

//     // Querying assignments for the deleted user returns an empty list,
//     // not a FK error.
//     let remaining = user_role_repo
//         .list_all_for_user(user_id)
//         .await
//         .expect("list_all_for_user after cascade should not error");

//     assert!(
//         remaining.is_empty(),
//         "assignments must be gone after user deletion"
//     );

//     cleanup_role_by_id(&role_repo, role.id)
//         .await
//         .expect("cleanup failed");
// }

// /// Deleting a role cascades to users_roles.
// #[tokio::test]
// async fn test_role_deletion_cascades_to_assignments() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user = create_test_user(&user_repo).await;
//     let role = create_test_role(&role_repo).await;
//     let role_id = role.id;

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user.id,
//             role_id,
//         })
//         .await
//         .expect("assign failed");

//     // Delete the role — cascade must remove the assignment row.
//     cleanup_role_by_id(&role_repo, role_id)
//         .await
//         .expect("role deletion should succeed even with assignments present");

//     let remaining = user_role_repo
//         .list_all_for_user(user.id)
//         .await
//         .expect("list_all_for_user after cascade should not error");

//     assert!(
//         remaining.is_empty(),
//         "assignments must be gone after role deletion"
//     );

//     cleanup_user_by_id(&user_repo, user.id)
//         .await
//         .expect("user cleanup failed");
// }

// /// Assignments for one user do not appear in another user's list.
// #[tokio::test]
// async fn test_assignments_are_isolated_per_user() {
//     let user_repo = make_user_repo().await;
//     let role_repo = make_role_repo().await;
//     let user_role_repo = make_user_role_repo().await;

//     let user_a = create_test_user(&user_repo).await;
//     let user_b = create_test_user(&user_repo).await;
//     let role = create_test_role(&role_repo).await;

//     user_role_repo
//         .assign(NewUserRole {
//             user_id: user_a.id,
//             role_id: role.id,
//         })
//         .await
//         .expect("assign to user_a failed");

//     let b_active = user_role_repo
//         .list_active_for_user(user_b.id)
//         .await
//         .expect("list_active_for_user for user_b failed");

//     assert!(
//         b_active.is_empty(),
//         "user_b must not see user_a's assignments"
//     );

//     cleanup_role_by_id(&role_repo, role.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user_a.id)
//         .await
//         .expect("cleanup failed");
//     cleanup_user_by_id(&user_repo, user_b.id)
//         .await
//         .expect("cleanup failed");
// }
