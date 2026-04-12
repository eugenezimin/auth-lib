-- -------------------------------------------------------------
-- Author: Eugene Zimin
-- Database: auth_lib
-- Generation Time: 2026-04-11 09:23:59.1900
-- Target:  MySQL / MariaDB
-- -------------------------------------------------------------

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `sessions` CASCADE;

DROP TABLE IF EXISTS `user_roles` CASCADE;

DROP TABLE IF EXISTS `users` CASCADE;

DROP TABLE IF EXISTS `roles` CASCADE;

SET FOREIGN_KEY_CHECKS = 1;

-- Table Definition
CREATE TABLE `sessions` (
    `id`                 CHAR(36)     NOT NULL DEFAULT (UUID()),
    `user_id`            CHAR(36)     NOT NULL,
    `access_token`       TEXT         NOT NULL,
    `access_created_at`  DATETIME(6)  NOT NULL,
    `access_expires_at`  DATETIME(6)  NOT NULL,
    `refresh_token`      TEXT         NOT NULL,
    `refresh_created_at` DATETIME(6)  NOT NULL,
    `refresh_expires_at` DATETIME(6)  NOT NULL,
    PRIMARY KEY (`id`),
    CONSTRAINT `fk_sessions_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table Definition
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

-- Table Definition
CREATE TABLE `roles` (
    `id`          CHAR(36)    NOT NULL DEFAULT (UUID()),
    `name`        VARCHAR(50) NOT NULL,
    `description` TEXT,
    `created_at`  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `roles_name_key` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table Definition
CREATE TABLE `user_roles` (
    `id`          CHAR(36)    NOT NULL DEFAULT (UUID()),
    `user_id`     CHAR(36)    NOT NULL,
    `role_id`     CHAR(36)    NOT NULL,
    `assigned_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `unique_user_role`      (`user_id`, `role_id`),
    KEY           `idx_user_roles_user_id` (`user_id`),
    KEY           `idx_user_roles_role_id` (`role_id`),
    CONSTRAINT `fk_user_roles_user_id`
        FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_user_roles_role_id`
        FOREIGN KEY (`role_id`) REFERENCES `roles`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Indices for sessions
CREATE INDEX `idx_sessions_user_id` ON `sessions` (`user_id`);

CREATE INDEX `idx_sessions_access_token`  ON `sessions` (`access_token`(255));

CREATE INDEX `idx_sessions_refresh_token` ON `sessions` (`refresh_token`(255));

CREATE INDEX `idx_sessions_user_id_expires` ON `sessions` (`user_id`, `access_expires_at` DESC);