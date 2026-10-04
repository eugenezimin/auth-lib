//! Validation of codes and permission values.

use crate::authorization::model::{
    Permission, PermissionAssignment, PermissionKind, PermissionValue,
};
use crate::constants::MAX_CODE_LEN;
use crate::error::AuthError;

/// Role, permission and option codes: `^[a-z][a-z0-9_.:-]*$`, at most
/// [`MAX_CODE_LEN`] characters.  Codes are immutable identifiers that end
/// up in tokens and application code.
pub fn validate_code(code: &str) -> Result<(), AuthError> {
    let mut chars = code.chars();
    let valid_start = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    let valid_rest = chars.all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '-')
    });
    if valid_start && valid_rest && code.len() <= MAX_CODE_LEN {
        Ok(())
    } else {
        Err(AuthError::InvalidCode(format!(
            "'{code}' must match ^[a-z][a-z0-9_.:-]*$ and be at most {MAX_CODE_LEN} characters"
        )))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::model::PermissionOption;
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
    fn codes() {
        for ok in ["admin", "reports.export", "a1_b-c:d"] {
            assert!(validate_code(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Admin",
            "1abc",
            "has space",
            "ünï",
            &"a".repeat(MAX_CODE_LEN + 1),
        ] {
            assert!(validate_code(bad).is_err(), "{bad}");
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
}
