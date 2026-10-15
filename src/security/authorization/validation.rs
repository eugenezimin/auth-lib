//! Validation of permission values.  Code syntax is checked by
//! [`crate::utils::validation::validate_code`].

use crate::security::authorization::model::{
    Permission, PermissionAssignment, PermissionKind, PermissionValue,
};
use crate::utils::error::AuthError;

/// Check `value` against `permission`'s kind and resolve option codes to
/// ids, producing what the repository stores.
pub fn assignment_for(
    permission: &Permission,
    value: &PermissionValue,
) -> Result<PermissionAssignment, AuthError> {
    let invalid = |reason: String| {
        AuthError::InvalidPermissionValue(format!("{}: {reason}", permission.code))
    };
    let option_id = |code: &str| {
        permission
            .options
            .iter()
            .find(|o| o.code == code)
            .map(|o| o.id)
            .ok_or_else(|| invalid(format!("unknown option '{code}'")))
    };

    let (option_ids, text) = match (permission.kind, value) {
        (PermissionKind::Bool, PermissionValue::Allow) => (vec![], None),
        (PermissionKind::Single, PermissionValue::Choice(code)) => (vec![option_id(code)?], None),
        (PermissionKind::Multi, PermissionValue::Choices(codes)) => {
            if codes.is_empty() {
                return Err(invalid("choose at least one option (or revoke)".into()));
            }
            let mut ids = codes
                .iter()
                .map(|c| option_id(c))
                .collect::<Result<Vec<_>, _>>()?;
            ids.sort();
            ids.dedup();
            (ids, None)
        }
        (PermissionKind::Text { max_length }, PermissionValue::Text(text)) => {
            if text.chars().count() > max_length as usize {
                return Err(invalid(format!("longer than {max_length} characters")));
            }
            (vec![], Some(text.clone()))
        }
        (kind, _) => return Err(invalid(format!("value does not fit kind {kind:?}"))),
    };
    Ok(PermissionAssignment {
        permission_id: permission.id,
        option_ids,
        text,
    })
}

/// The inverse of [`assignment_for`]: the value a stored assignment grants,
/// with option ids resolved back to codes in catalog order.  `None` if the
/// assignment does not fit the permission (e.g. an option it doesn't have).
pub fn value_of(
    permission: &Permission,
    assignment: &PermissionAssignment,
) -> Option<PermissionValue> {
    let codes: Vec<String> = permission
        .options
        .iter()
        .filter(|o| assignment.option_ids.contains(&o.id))
        .map(|o| o.code.clone())
        .collect();
    if codes.len() != assignment.option_ids.len() {
        return None;
    }
    match permission.kind {
        PermissionKind::Bool => Some(PermissionValue::Allow),
        PermissionKind::Single => match codes.as_slice() {
            [code] => Some(PermissionValue::Choice(code.clone())),
            _ => None,
        },
        PermissionKind::Multi if !codes.is_empty() => Some(PermissionValue::Choices(codes)),
        PermissionKind::Multi => None,
        PermissionKind::Text { .. } => assignment.text.clone().map(PermissionValue::Text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::authorization::model::PermissionOption;
    use uuid::Uuid;

    fn permission(kind: PermissionKind, options: &[&str]) -> Permission {
        Permission {
            id: Uuid::new_v4(),
            code: "p".into(),
            kind,
            description: None,
            position: None,
            options: options
                .iter()
                .enumerate()
                .map(|(i, c)| PermissionOption {
                    id: Uuid::new_v4(),
                    code: (*c).into(),
                    position: i as u32,
                })
                .collect(),
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn values_must_fit_the_kind() {
        let multi = permission(PermissionKind::Multi, &["csv", "pdf"]);
        let a = assignment_for(
            &multi,
            &PermissionValue::Choices(vec!["pdf".into(), "pdf".into()]),
        )
        .unwrap();
        assert_eq!(a.option_ids.len(), 1, "deduplicated");
        assert!(assignment_for(&multi, &PermissionValue::Choices(vec![])).is_err());
        assert!(assignment_for(&multi, &PermissionValue::Choices(vec!["xls".into()])).is_err());
        assert!(assignment_for(&multi, &PermissionValue::Allow).is_err());

        let single = permission(PermissionKind::Single, &["eu", "us"]);
        assert_eq!(
            assignment_for(&single, &PermissionValue::Choice("us".into()))
                .unwrap()
                .option_ids,
            vec![single.options[1].id]
        );

        let text = permission(PermissionKind::Text { max_length: 3 }, &[]);
        assert!(assignment_for(&text, &PermissionValue::Text("abc".into())).is_ok());
        assert!(assignment_for(&text, &PermissionValue::Text("abcd".into())).is_err());

        let flag = permission(PermissionKind::Bool, &[]);
        assert!(assignment_for(&flag, &PermissionValue::Allow).is_ok());
        assert!(assignment_for(&flag, &PermissionValue::Text("x".into())).is_err());
    }

    #[test]
    fn value_of_inverts_assignment_for() {
        let multi = permission(PermissionKind::Multi, &["csv", "pdf", "xlsx"]);
        for (p, value) in [
            (
                multi.clone(),
                PermissionValue::Choices(vec!["csv".into(), "xlsx".into()]),
            ),
            (
                permission(PermissionKind::Single, &["eu", "us"]),
                PermissionValue::Choice("us".into()),
            ),
            (
                permission(PermissionKind::Text { max_length: 8 }, &[]),
                PermissionValue::Text("50".into()),
            ),
            (permission(PermissionKind::Bool, &[]), PermissionValue::Allow),
        ] {
            let a = assignment_for(&p, &value).unwrap();
            assert_eq!(value_of(&p, &a), Some(value));
        }

        let unknown = PermissionAssignment {
            permission_id: multi.id,
            option_ids: vec![Uuid::new_v4()],
            text: None,
        };
        assert_eq!(value_of(&multi, &unknown), None, "unknown option");
    }
}
