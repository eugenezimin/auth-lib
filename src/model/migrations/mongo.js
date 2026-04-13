// -------------------------------------------------------------
// Author: Eugene Zimin
// Database: auth_lib
// Generation Time: 2026-04-13
// Target:  MongoDB 6.0+
// -------------------------------------------------------------
//
// Run with:
//   mongosh "mongodb://localhost:27017" --file mongo.js
//
// The script is idempotent — safe to re-run.  Existing collections
// are dropped and recreated, so do NOT run against production data
// without a backup.
// -------------------------------------------------------------

const DB_NAME = "auth_lib";
const db = db.getSiblingDB(DB_NAME);

// ── helpers ───────────────────────────────────────────────────────────────────

function drop(name) {
    if (db.getCollectionNames().includes(name)) {
        db[name].drop();
        print(`  dropped   : ${name}`);
    }
}

function create(name, validator, indexes) {
    db.createCollection(name, {
        validator: { $jsonSchema: validator },
        validationLevel:  "strict",
        validationAction: "error",
    });
    print(`  created   : ${name}`);

    if (indexes && indexes.length > 0) {
        db[name].createIndexes(indexes);
        print(`  indexed   : ${name} (${indexes.length} index(es))`);
    }
}

// ── drop order matters: dependants first ──────────────────────────────────────

print("\n── Dropping collections ─────────────────────────────────────────────────");
drop("sessions");
drop("user_roles");
drop("users");
drop("roles");

// ── roles ─────────────────────────────────────────────────────────────────────
print("\n── Creating collections ─────────────────────────────────────────────────");

create(
    "roles",
    {
        bsonType: "object",
        required: ["_id", "name", "created_at"],
        additionalProperties: false,
        properties: {
            _id: {
                bsonType: "binData",
                description: "UUID v4 stored as BinData subtype 4",
            },
            name: {
                bsonType: "string",
                minLength: 1,
                maxLength: 50,
                description: "Unique role name — required",
            },
            description: {
                bsonType: ["string", "null"],
                description: "Optional human-readable description",
            },
            created_at: {
                bsonType: "date",
                description: "UTC creation timestamp — required",
            },
        },
    },
    [
        {
            key:    { name: 1 },
            name:   "roles_name_key",
            unique: true,
        },
    ]
);

// ── users ─────────────────────────────────────────────────────────────────────

create(
    "users",
    {
        bsonType: "object",
        required: ["_id", "email", "is_active", "is_verified", "created_at", "updated_at"],
        additionalProperties: false,
        properties: {
            _id: {
                bsonType: "binData",
            },
            email: {
                bsonType: "string",
                maxLength: 255,
                pattern: "^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$",
                description: "Unique email address — required",
            },
            password_hash: {
                bsonType: ["string", "null"],
                description: "Argon2id hash; null for OAuth-only accounts",
            },
            jwt_secret: {
                bsonType: ["string", "null"],
                description: "Per-user HMAC secret; rotating invalidates all tokens",
            },
            username: {
                bsonType: ["string", "null"],
                maxLength: 100,
                description: "Unique display handle; null if not set",
            },
            first_name: {
                bsonType: ["string", "null"],
                maxLength: 255,
            },
            last_name: {
                bsonType: ["string", "null"],
                maxLength: 255,
            },
            avatar_url: {
                bsonType: ["string", "null"],
            },
            is_active: {
                bsonType: "bool",
                description: "false = soft-deleted / suspended",
            },
            is_verified: {
                bsonType: "bool",
                description: "true once the user confirms their email",
            },
            created_at: {
                bsonType: "date",
            },
            updated_at: {
                bsonType: "date",
            },
        },
    },
    [
        {
            key:    { email: 1 },
            name:   "users_email",
            unique: true,
        },
        {
            // sparse so that documents where username is null are excluded —
            // equivalent to the PostgreSQL partial unique index on non-null values.
            key:    { username: 1 },
            name:   "users_username_key",
            unique: true,
            sparse: true,
        },
    ]
);

// ── user_roles ────────────────────────────────────────────────────────────────
// revoked_at is absent (or null) while the assignment is active.
// A partial unique index on { user_id, role_id } WHERE revoked_at does not
// exist replicates the PostgreSQL partial-index semantics exactly.

create(
    "user_roles",
    {
        bsonType: "object",
        required: ["_id", "user_id", "role_id", "assigned_at"],
        additionalProperties: false,
        properties: {
            _id: {
                bsonType: "binData",
            },
            user_id: {
                bsonType: "binData",
                description: "Reference to users._id",
            },
            role_id: {
                bsonType: "binData",
                description: "Reference to roles._id",
            },
            assigned_at: {
                bsonType: "date",
            },
            // Omitting revoked_at from `required` makes it optional, which
            // correctly models NULL in SQL.  The validator allows it to be a
            // date or explicitly null.
            revoked_at: {
                bsonType: ["date", "null"],
                description: "null / absent = active; set = revoked",
            },
        },
    },
    [
        // Active-assignment uniqueness: only one active (user, role) pair.
        // partialFilterExpression is MongoDB's equivalent of WHERE revoked_at IS NULL.
        {
            key:    { user_id: 1, role_id: 1 },
            name:   "unique_user_role_active",
            unique: true,
            partialFilterExpression: { revoked_at: { $exists: false } },
        },
        // Fast lookup of all assignments (active + revoked) for a user.
        {
            key:  { user_id: 1, assigned_at: -1 },
            name: "idx_user_roles_user_id",
        },
        // Fast lookup of active assignments only.
        {
            key:  { user_id: 1, assigned_at: -1 },
            name: "idx_user_roles_active",
            partialFilterExpression: { revoked_at: { $exists: false } },
        },
        // Fast lookup of revoked assignments (audit / reporting).
        {
            key:  { user_id: 1, revoked_at: -1 },
            name: "idx_user_roles_removed",
            partialFilterExpression: { revoked_at: { $exists: true } },
        },
        {
            key:  { role_id: 1 },
            name: "idx_user_roles_role_id",
        },
    ]
);

// ── sessions ──────────────────────────────────────────────────────────────────

create(
    "sessions",
    {
        bsonType: "object",
        required: [
            "_id",
            "user_id",
            "access_token",
            "access_created_at",
            "access_expires_at",
            "refresh_token",
            "refresh_created_at",
            "refresh_expires_at",
        ],
        additionalProperties: false,
        properties: {
            _id: {
                bsonType: "binData",
            },
            user_id: {
                bsonType: "binData",
                description: "Reference to users._id",
            },
            access_token: {
                bsonType: "string",
            },
            access_created_at: {
                bsonType: "date",
            },
            access_expires_at: {
                bsonType: "date",
            },
            refresh_token: {
                bsonType: "string",
            },
            refresh_created_at: {
                bsonType: "date",
            },
            refresh_expires_at: {
                bsonType: "date",
            },
        },
    },
    [
        {
            key:  { user_id: 1 },
            name: "idx_sessions_user_id",
        },
        {
            key:    { access_token: 1 },
            name:   "idx_sessions_access_token",
            unique: true,
        },
        {
            key:    { refresh_token: 1 },
            name:   "idx_sessions_refresh_token",
            unique: true,
        },
        // TTL index: MongoDB automatically deletes expired session documents.
        // The document is removed expireAfterSeconds after access_expires_at.
        {
            key:  { access_expires_at: 1 },
            name: "idx_sessions_ttl",
            expireAfterSeconds: 0,
        },
        {
            key:  { user_id: 1, access_expires_at: -1 },
            name: "idx_sessions_user_id_expires",
        },
    ]
);

print("\n── Done ─────────────────────────────────────────────────────────────────\n");