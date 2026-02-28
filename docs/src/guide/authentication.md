# Authentication

Rusty Socks v0.2.0 uses **JWT (JSON Web Tokens)** for authenticating WebSocket connections and **Role-Based Access Control (RBAC)** for permissions. This guide covers the jsonwebtoken v10.3.0 integration, the available roles (Owner, Admin, Moderator, Member, Guest), and how tokens and claims are validated. The design reflects the 2026 audit baseline for authentication and secret handling.

## JWT Integration (jsonwebtoken v10.3.0)

### Dependency

In `Cargo.toml`, the crate is pinned to version 10.3.0 with the **aws_lc_rs** crypto backend:

```toml
jsonwebtoken = { version = "=10.3.0", features = ["aws_lc_rs"] }
```

Pinning and an explicit crypto feature support reproducible builds and a clear cryptographic stack.

### TokenManager

The **TokenManager** (`auth::token`) centralizes JWT creation and validation:

- **Keys**: `EncodingKey` and `DecodingKey` are built from the shared secret (`from_secret(secret.as_bytes())`).
- **Validation**: The library’s default validation (e.g. `exp`, `nbf`) is used via `Validation::default()`.
- **Encoding**: `generate_token(&self, claims: &Claims) -> Result<String>` uses `encode(&Header::default(), claims, &self.encoding_key)`.
- **Decoding**: `validate_token(&self, token: &str) -> Result<TokenData<Claims>>` uses `decode::<Claims>(token, &self.decoding_key, &self.validation)`. If a revocation store is configured, the token’s identifier (e.g. `jti`) is checked before returning; revoked tokens are rejected.
- **Claims**: `get_claims(&self, token: &str) -> Result<Claims>` calls `validate_token` and returns the decoded claims. This is the path used when authenticating a WebSocket connection.

TokenManager can be constructed with `new(secret)` or `with_revocation_store(secret, revocation_store)` to enable revocation checks.

### Claims Structure

The JWT payload is represented by **Claims** (`auth::token`):

| Field      | Type              | Description                          |
|-----------|-------------------|--------------------------------------|
| `sub`     | String            | Subject (user ID)                    |
| `username`| `Option<String>`  | Display name                         |
| `exp`     | usize             | Expiration (UTC timestamp)           |
| `iat`     | usize             | Issued at (UTC timestamp)            |
| `nbf`     | usize             | Not before (UTC timestamp)           |
| `email`   | `Option<String>`  | Email (optional)                     |
| `iss`     | `Option<String>`  | Issuer (optional)                    |
| `aud`     | `Option<String>`  | Audience (optional)                  |
| `jti`     | `Option<String>`  | JWT ID (for revocation)              |

Helpers include `Claims::new`, `Claims::with_expiration`, `get_token_id()` (for revocation), and `is_expired()`.

### Token Extraction (Headers Only)

Tokens are taken **only from headers**; the URL is not used, to avoid exposure in logs, history, and Referer.

**extract_token_comprehensive** (`handlers::auth`) tries, in order:

1. **Authorization** — `Authorization: Bearer <token>` (via `extract_bearer_token`).
2. **Sec-WebSocket-Protocol** — value like `bearer.<token>` or `token.<token>`.
3. **X-Auth-Token** — custom header with the raw token.

`extract_token_from_url` is disabled and always returns `None`; it logs a security message directing use of the above headers.

### Validation in authenticate_connection

After decoding, the handler applies extra checks:

- Token length > 1000 → reject (“Token too long”).
- Any control character in the token → reject (“Token contains invalid characters”).
- Empty `sub` or `username` → reject (“Invalid token claims”).
- `sub` length > 100 or `username` length > 50 → reject (“Token claims too long”).

An **AuthTimer** enforces a minimum duration (e.g. 100 ms) before responding, to reduce timing side-channels. On failure, the client receives a generic “Authentication failed” message; no detailed error is exposed.

## Role-Based Access Control (RBAC)

Permissions are modeled as **roles** per room (and optionally a **global role** on the user). The server checks the user’s role before allowing actions such as sending messages, managing the room, or moderating users.

### Available Roles

Roles are defined in `auth::user::UserRole`:

| Role        | Description                                  |
|-------------|----------------------------------------------|
| **Owner**   | Full control over the room and roles.        |
| **Admin**   | Manage roles and moderate; no room ownership.|
| **Moderator** | Kick, mute, send/delete messages.           |
| **Member**  | Send messages and invite users.              |
| **Guest**   | Send messages only.                          |

### Permissions per Role

Each role has a fixed set of **Permission** flags. The following lists are defined in `UserRole::permissions()` in `src/auth/user.rs`:

- **Owner**: `ManageRoom`, `ManageRoles`, `KickUsers`, `BanUsers`, `MuteUsers`, `SendMessages`, `DeleteMessages`, `InviteUsers`, `CreateRooms`.
- **Admin**: Same as Owner except **no** `ManageRoom` (cannot transfer/delete the room itself).
- **Moderator**: `KickUsers`, `MuteUsers`, `SendMessages`, `DeleteMessages` (no role management, ban, or room creation).
- **Member**: `SendMessages`, `InviteUsers`.
- **Guest**: `SendMessages` only.

Permission checks use `UserRole::has_permission(permission)`. Room-level roles are stored in the room (e.g. `RoomManager` / `user_roles`); the **User** struct also has an optional **global_role** used for server-wide privileges (e.g. default `Member` for authenticated users in `handlers::auth::authenticate_connection`).

### Permission Enum

`auth::user::Permission` defines the actions that can be gated by RBAC:

- `ManageRoom` — Create, delete, configure rooms.
- `ManageRoles` — Assign or remove roles.
- `KickUsers` — Remove users from a room.
- `BanUsers` — Ban users from a room.
- `MuteUsers` — Mute users in a room.
- `SendMessages` — Send messages to the room.
- `DeleteMessages` — Delete any message.
- `InviteUsers` — Invite users to the room.
- `CreateRooms` — Create new rooms.

Handlers (e.g. message handler, token management, room operations) resolve the user’s role for the relevant room (or global) and call `has_permission` before performing the action. Role assignment (e.g. `SetUserRole` with strings like `"owner"`, `"admin"`, `"moderator"`, `"member"`, `"guest"`) is parsed to `UserRole` and stored by the room or storage layer.

## Summary

- **JWT**: jsonwebtoken 10.3.0 with `aws_lc_rs`; TokenManager for encode/decode and optional revocation.
- **Claims**: Standard fields including `sub`, `username`, `exp`, `iat`, `nbf`, `jti`; strict validation and length limits after decode.
- **Extraction**: Headers only (Authorization Bearer, Sec-WebSocket-Protocol, X-Auth-Token); no URL.
- **RBAC**: Five roles — Owner, Admin, Moderator, Member, Guest — with defined permissions; room-level and optional global role; checks performed before sensitive operations.

These choices align with the 2026 audit’s recommendations for authentication, token handling, and role-based access control.
