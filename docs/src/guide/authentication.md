# Authentication

We use **JWT (JSON Web Tokens)** to authenticate WebSocket connections and **roles** (Owner, Admin, Moderator, Member, Guest) to control what users can do. This guide walks through our jsonwebtoken v10.3.0 setup, how we validate tokens and claims, and how RBAC works. Everything here is aligned with the 2026 audit's recommendations for auth and secret handling.

## JWT: How We Use jsonwebtoken v10.3.0

We pin to **jsonwebtoken 10.3.0** and use the **aws_lc_rs** crypto backend so we have a clear, reproducible crypto stack. You'll find it in `Cargo.toml` as:

```toml
jsonwebtoken = { version = "=10.3.0", features = ["aws_lc_rs"] }
```

**TokenManager** (`auth::token`) is the single place we create and validate tokens. We build encoding/decoding keys from the shared secret, use the library's default validation (so `exp` and `nbf` are checked), and optionally plug in a revocation store. When we validate a token we decode it, then check revocation (by `jti` or a derived id) if the store is configured—only then do we return the claims. So when you're debugging auth, think: decode → revoke check → claim checks. We use `get_claims` for the WebSocket auth path.

### What's in the Token (Claims)

Our JWT payload is the **Claims** struct: `sub` (user id), `username`, `exp`, `iat`, `nbf`, and optional `email`, `iss`, `aud`, `jti`. We use `jti` (or a hash of the token if `jti` is missing) for revocation. Helpers like `Claims::new`, `Claims::with_expiration`, `get_token_id()`, and `is_expired()` are there when you need to issue or inspect tokens.

| Field      | Type              | Description                |
|-----------|-------------------|----------------------------|
| `sub`     | String            | Subject (user ID)          |
| `username`| `Option<String>`  | Display name               |
| `exp`     | usize             | Expiration (UTC)          |
| `iat`     | usize             | Issued at (UTC)            |
| `nbf`     | usize             | Not before (UTC)           |
| `email`   | `Option<String>`  | Email (optional)           |
| `iss`     | `Option<String>`  | Issuer (optional)          |
| `aud`     | `Option<String>`  | Audience (optional)        |
| `jti`     | `Option<String>`  | JWT ID (for revocation)    |

### Where We Take the Token From (Headers Only)

We **never** read the token from the URL. That would leak it into logs, browser history, and Referer headers. So we only look at headers. **extract_token_comprehensive** tries, in order: (1) `Authorization: Bearer <token>`, (2) `Sec-WebSocket-Protocol` with `bearer.<token>` or `token.<token>`, (3) `X-Auth-Token`. If you're building a client, use one of those; `extract_token_from_url` is disabled and will always return `None` (and log a security warning).

### What We Check After Decoding

After we decode the token, we apply a few extra checks so we don't trust malformed or oversized claims: token length > 1000, any control character in the token, empty `sub` or `username`, or `sub`/`username` too long (e.g. sub > 100, username > 50). We also use an **AuthTimer** to enforce a minimum response time (e.g. 100 ms) so we don't leak information via timing. On failure we send a generic "Authentication failed" message—no details. Be careful with adding new error messages; the 2026 audit pushed us to keep auth errors generic so we don't help an attacker.

## Roles: Owner, Admin, Moderator, Member, Guest

Permissions are modeled as **roles** per room (and optionally a **global role** on the user). Before we do something sensitive (send a message, kick a user, create a room, etc.) we resolve the user's role and check the right permission.

### The Five Roles

We have five roles, from most to least privileged:

| Role          | What they're for |
|---------------|------------------|
| **Owner**     | Full control over the room and roles. |
| **Admin**     | Manage roles and moderate; can't transfer/delete the room itself. |
| **Moderator** | Kick, mute, send/delete messages. |
| **Member**    | Send messages and invite users. |
| **Guest**     | Send messages only. |

Each role has a fixed set of **Permission** flags (e.g. `ManageRoom`, `ManageRoles`, `KickUsers`, `SendMessages`, …). The exact lists live in `UserRole::permissions()` in `src/auth/user.rs`. Owner has everything; Admin has everything except `ManageRoom`; Moderator has kick/mute/send/delete; Member has send and invite; Guest has send only. When we need to check an action, we call `UserRole::has_permission(permission)`. Room-level roles are stored in the room (e.g. `RoomManager`); the **User** struct also has an optional **global_role** for server-wide privileges—for example we set default `Member` for authenticated users when they connect.

### Permissions We Gate On

The **Permission** enum covers: `ManageRoom`, `ManageRoles`, `KickUsers`, `BanUsers`, `MuteUsers`, `SendMessages`, `DeleteMessages`, `InviteUsers`, `CreateRooms`. Handlers (message handler, token management, room ops) resolve the user's role for the relevant room (or global) and call `has_permission` before doing the action. When someone sets a role (e.g. via `SetUserRole` with strings like `"owner"`, `"admin"`, `"moderator"`, `"member"`, `"guest"`), we parse that to `UserRole` and store it. So if you're adding a new action, make sure you gate it on the right permission and document which role has it.

## Wrapping Up

- **JWT**: jsonwebtoken 10.3.0, TokenManager, optional revocation, claims validated and length-limited.
- **Extraction**: Headers only; no URL.
- **RBAC**: Five roles (Owner, Admin, Moderator, Member, Guest) with clear permissions; room-level and optional global role; checks before sensitive operations.

If you're onboarding or contributing, start with "where does the token come from?" and "what role does this user have for this room?"—that'll get you most of the way.
