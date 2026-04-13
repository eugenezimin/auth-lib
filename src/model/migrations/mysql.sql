-- -------------------------------------------------------------
-- Author: Eugene Zimin
-- Database: auth_lib
-- Generation Time: 2026-04-13
-- Target:  MySQL / MariaDB
-- -------------------------------------------------------------

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `sessions`;
DROP TABLE IF EXISTS `user_roles`;
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `roles`;

SET FOREIGN_KEY_CHECKS = 1;

-- ── roles ─────────────────────────────────────────────────────────────────────
CREATE TABLE `roles` (
    `id`          CHAR(36)    NOT NULL DEFAULT (UUID()),
    `name`        VARCHAR(50) NOT NULL,
    `description` TEXT,
    `created_at`  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `roles_name_key` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── users ─────────────────────────────────────────────────────────────────────
CREATE TABLE `users` (
    `id`            CHAR(36)     NOT NULL DEFAULT (UUID()),
    `email`         VARCHAR(255) NOT NULL,
    `password_hash` TEXT,
    `jwt_secret`    TEXT,
    `username`      VARCHAR(100),
    `first_name`    VARCHAR(255),
    `last_name`     VARCHAR(255),
    `avatar_url`    TEXT,
    `is_active`     TINYINT(1)   NOT NULL DEFAULT 1,
    `is_verified`   TINYINT(1)   NOT NULL DEFAULT 0,
    `created_at`    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at`    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `users_email`        (`email`),
    UNIQUE KEY `users_username_key` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ── user_roles ────────────────────────────────────────────────────────────────
-- removed_at is NULL while the assignment is active; set to the revocation
-- timestamp when the role is withdrawn.  This keeps the full audit trail
-- without a separate history table.
--
-- Note: MySQL does not support partial (filtered) indexes, so the active-only
-- uniqueness guarantee that PostgreSQL enforces via
--   CREATE UNIQUE INDEX … WHERE removed_at IS NULL
-- cannot be expressed directly in DDL here.  The application layer (or a
-- BEFORE INSERT trigger below) must enforce that a user cannot hold the same
-- role twice concurrently.
CREATE TABLE `user_roles` (
    `id`          CHAR(36)    NOT NULL DEFAULT (UUID()),
    `user_id`     CHAR(36)    NOT NULL,
    `role_id`     CHAR(36)    NOT NULL,
    `assigned_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `removed_at`  DATETIME(6)          DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_user_roles_user_id` (`user_id`),
    KEY `idx_user_roles_role_id` (`role_id`),
    KEY `idx_user_roles_assigned_at` (`user_id`, `assigned_at` DESC),
    KEY `idx_user_roles_removed_at`  (`user_id`, `removed_at`  DESC),
    CONSTRAINT `fk_user_roles_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_user_roles_role_id`
        FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Active-assignment uniqueness guard.
-- Fires before every INSERT on user_roles.  If the user already holds the
-- role with removed_at IS NULL the signal aborts the statement with a clear
-- SQLSTATE '45000' error that the application can catch and map to
-- AuthError::RoleAlreadyAssigned (or similar).
DELIMITER $$

CREATE TRIGGER `trg_user_roles_no_duplicate_active`
BEFORE INSERT ON `user_roles`
FOR EACH ROW
BEGIN
    DECLARE v_count INT;

    SELECT COUNT(*) INTO v_count
    FROM `user_roles`
    WHERE `user_id`    = NEW.user_id
      AND `role_id`    = NEW.role_id
      AND `removed_at` IS NULL;

    IF v_count > 0 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'user already holds this role (active assignment exists)';
    END IF;
END$$

DELIMITER ;

-- ── sessions ──────────────────────────────────────────────────────────────────
CREATE TABLE `sessions` (
    `id`                 CHAR(36)    NOT NULL DEFAULT (UUID()),
    `user_id`            CHAR(36)    NOT NULL,
    `access_token`       TEXT        NOT NULL,
    `access_created_at`  DATETIME(6) NOT NULL,
    `access_expires_at`  DATETIME(6) NOT NULL,
    `refresh_token`      TEXT        NOT NULL,
    `refresh_created_at` DATETIME(6) NOT NULL,
    `refresh_expires_at` DATETIME(6) NOT NULL,
    PRIMARY KEY (`id`),
    -- TEXT columns cannot be indexed without a prefix length in MySQL.
    -- 255 covers the realistic token head needed for selective lookups;
    -- the full value is still stored and returned without truncation.
    KEY `idx_sessions_user_id`      (`user_id`),
    KEY `idx_sessions_access_token`  (`access_token`(255)),
    KEY `idx_sessions_refresh_token` (`refresh_token`(255)),
    KEY `idx_sessions_user_id_expires` (`user_id`, `access_expires_at` DESC),
    CONSTRAINT `fk_sessions_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;