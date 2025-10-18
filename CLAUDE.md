# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Shorter is a URL shortening service built with Rust, using Axum for the web framework, sea-orm for database operations, and SQLite for data storage. The application creates short tags that redirect to longer URLs, with support for custom tags and user ownership via OpenID Connect (OIDC) authentication.

## Development Commands

### Building and Running
```bash
cargo build                    # Build the project
cargo run                      # Run the server (default: http://127.0.0.1:9000)
cargo run -- --listener-addr 127.0.0.1:8080  # Run on custom address
```

### Testing
```bash
cargo test                     # Run all tests
cargo test test_post_link      # Run specific test by name
cargo test --lib               # Run only library tests
cargo test -- --nocapture      # Run tests with output visible
```

### Code Quality
```bash
cargo check                    # Quick compile check
cargo clippy                   # Lint the code
cargo fmt                      # Format code
```

## Architecture

### Core Components

**Database Layer** (`src/db.rs`)
- `DB` struct wraps sea-orm `DatabaseConnection`
- Automatic migration execution on startup via sea-orm-migration
- Three tables: `users`, `links` (with foreign key to users), `pkce_states` (for OAuth flow)
- Methods for CRUD operations on all entities
- `DB::new()` for file-based database, `DB::new_memory()` for testing (returns tuple with temp file)
- Single connection pool (max_connections=1) for SQLite to avoid concurrency issues

**Migration System** (`migration/` directory)
- Uses sea-orm-migration framework
- Automatic migration on app startup
- Initial migration: `m20250118_000001_create_tables.rs` creates all tables with proper foreign keys and indexes
- Migrations tracked in `seaql_migrations` table

**Application State** (`src/lib.rs`)
- `AppState` contains:
  - `db`: DB instance (sea-orm connection)
  - `oauth_client`: Optional Arc-wrapped OAuthClient for OIDC authentication
- State shared across handlers via Axum's `State` extractor
- Session management via tower-sessions with MemoryStore
- 24-hour session expiry on inactivity

**Authentication** (`src/auth/` module)
- **OAuth Client** (`oauth.rs`): OIDC authentication with PKCE (Proof Key for Code Exchange)
  - Supports OIDC discovery from issuer URL
  - Requests scopes: openid, profile, email
  - Stores PKCE state in database (10-minute expiry)
  - No client secret required (public client with PKCE)
- **Middleware** (`middleware.rs`): Authentication enforcement
  - `require_auth` middleware checks session for authenticated user
  - Loads user from database and adds `AuthUser` to request extensions
  - Redirects to `/auth/login` if not authenticated

**Data Models**

sea-orm Entities (`src/entities/`):
- `user::Model`: OIDC-based user with subject (OIDC sub claim), email, display_name
- `link::Model`: URL shortening with owner_subject (foreign key), name, target, tag
- `pkce_state::Model`: Temporary storage for OAuth PKCE flow state

Response Types:
- `LinkWithOwner`: Serializable struct combining link data with Url type for API responses
- `CreateLinkApiRequest`: JSON input for link creation API
- `LinkFormData`: HTML form input for admin UI

**API Endpoints** (`src/lib.rs`)

Public Routes:
- `GET /` - Root handler redirects to /admin/
- `GET /favicon.ico` - Favicon handler (returns 204 No Content)
- `POST /link` - Create new short link (JSON body with owner_subject)
- `GET /{tag}` - Redirect to target URL for the given tag
- `GET /{tag}/preview` - Preview endpoint (placeholder)

Auth Routes:
- `GET /auth/login` - Initiates OIDC login flow
- `GET /auth/callback` - OIDC callback handler (exchanges code for tokens)
- `GET /auth/logout` - Clears session and logs out user

Admin Routes (require authentication):
- `GET /admin/` - List all links with owner information
- `GET /admin/create` - Create link form
- `POST /admin/create` - Submit create link (auto-assigns owner from session)
- `GET /admin/edit/{id}` - Edit link form
- `POST /admin/edit/{id}` - Submit edit link
- `POST /admin/delete/{id}` - Delete link

**Error Handling** (`src/error.rs`)
- Custom `MyError` enum with variants for:
  - DatabaseError: sea-orm database errors (stored as String)
  - UrlParseError: URL parsing failures
  - OidcDiscovery: OIDC provider discovery failures
  - OidcStateParameterExpired: OAuth state parameter validation failures
  - Other: General errors
- Implements conversions from common error types

### Key Implementation Details

**OIDC Configuration**
- Only requires 2 environment variables:
  - `SHORTER_OIDC_DISCOVERY_URL`: OIDC issuer URL for discovery
  - `SHORTER_OIDC_CLIENT_ID`: OAuth2 client ID
- Redirect URI constructed from `SHORTER_FRONTEND_URL`: `{SHORTER_FRONTEND_URL}/auth/callback`
- Uses OIDC discovery to fetch provider metadata dynamically
- Frontend URL allows proper configuration behind reverse proxies or load balancers

**Tag Generation**
- If no custom tag provided, auto-generates tag from first 8 characters of UUID
- Banned tags: "link", "admin", "preview" (validated in create, edit, and lookup)
- Empty tags in forms are treated as None (auto-generation)

**User Management**
- Users created on first login via `get_or_create_user()`
- Primary identifier: `subject` (OIDC sub claim)
- User info displayed in admin UI navigation
- Links owned by user's subject identifier

**Session Management**
- Uses tower-sessions with MemoryStore
- Stores `user_subject` in session on successful login
- 24-hour expiry on inactivity
- Session cleared on logout

**Testing Approach**
- Tests use temporary file-based SQLite database to ensure schema persistence
- `DB::new_memory()` returns tuple: `(DB, NamedTempFile)` - caller must keep temp file alive
- `AppState::new_memory()` wraps DB method, returns `(Result<AppState>, NamedTempFile)`
- Uses Axum's `Router::oneshot()` for testing HTTP requests
- Tests compile and run (some have schema persistence issues being debugged)

## Environment Variables

### Required for Basic Operation
- `SHORTER_LISTENER_ADDR` - Server bind address (default: 127.0.0.1:9000)
- `SHORTER_FRONTEND_URL` - Public-facing URL of the site (e.g., https://short.example.com) **REQUIRED**
  - Used for OIDC redirect URI construction
  - Should be the external URL users access, not the internal listener address
  - Do not include trailing slash
- `SHORTER_TLS_CERT` - Path to TLS certificate file (PEM format) **REQUIRED**
- `SHORTER_TLS_KEY` - Path to TLS private key file (PEM format) **REQUIRED**

### Required for OIDC Authentication
- `SHORTER_OIDC_DISCOVERY_URL` - OIDC provider issuer URL (e.g., https://accounts.google.com)
- `SHORTER_OIDC_CLIENT_ID` - OAuth2 client ID from your OIDC provider

### Optional
- If OIDC variables not provided, app runs without authentication (public mode)

### HTTPS-Only Mode
- The application **only** supports HTTPS - HTTP is not supported
- TLS certificates are required for all deployments
- Session cookies are marked as secure (HTTPS only)
- OIDC redirect URI constructed from `SHORTER_FRONTEND_URL` as `{SHORTER_FRONTEND_URL}/auth/callback`

## Database Schema

**users table:**
- id (INTEGER, auto-increment, primary key)
- subject (TEXT, unique): OIDC subject claim (primary identifier)
- email (TEXT, unique): User email from OIDC
- display_name (TEXT, nullable): User display name
- created_at (TIMESTAMP): User creation time
- updated_at (TIMESTAMP): Last update time

**links table:**
- id (TEXT, UUID, primary key)
- owner_subject (TEXT, foreign key to users.subject): Link owner
- name (TEXT): Descriptive name
- target (TEXT): Full URL to redirect to
- tag (TEXT, unique): Short identifier used in URLs
- created_at (TIMESTAMP): Link creation time
- updated_at (TIMESTAMP): Last update time
- Index on owner_subject for performance

**pkce_states table:**
- state (TEXT, primary key): OAuth state parameter
- code_verifier (TEXT): PKCE code verifier
- nonce (TEXT): OIDC nonce
- code_challenge (TEXT): PKCE code challenge
- redirect_uri (TEXT): OAuth redirect URI
- expires_at (TIMESTAMP): State expiration time (10 minutes)
- created_at (TIMESTAMP): State creation time
- Index on expires_at for cleanup operations

### Foreign Keys
- links.owner_subject → users.subject (CASCADE on delete/update)

## Module Structure

- `main.rs` - Entry point, CLI parsing, OIDC config, server initialization
- `lib.rs` - Main application logic, routing, handlers, form structs
- `db.rs` - Database layer with CRUD operations for all entities
- `error.rs` - Error types and conversions
- `prelude.rs` - Common re-exports (DB, MyError)
- `auth/` - Authentication module
  - `mod.rs` - Module exports
  - `oauth.rs` - OIDC client with PKCE support
  - `middleware.rs` - Authentication middleware and AuthUser type
- `entities/` - sea-orm entity models
  - `mod.rs` - Entity module exports
  - `user.rs` - User entity
  - `link.rs` - Link entity with foreign key relation
  - `pkce_state.rs` - PKCE state entity
- `tests.rs` - Integration tests (cfg(test))
- `templates/` - Askama HTML templates for admin UI (no JavaScript)
  - `base.html` - Base layout with navigation, user info, and CSS
  - `admin_list.html` - List all links with owner information
  - `admin_create.html` - Create link form (owner auto-assigned)
  - `admin_edit.html` - Edit link form
- `migration/` - Database migrations
  - `src/lib.rs` - Migration trait implementation
  - `src/m20250118_000001_create_tables.rs` - Initial schema migration

## Dependencies

Key crates:
- `axum` (0.8): Web framework
- `axum-server` (0.7): HTTPS server with TLS support
- `sea-orm` (1.1): ORM with SQLite support
- `sea-orm-migration` (1.1): Database migrations
- `openidconnect` (3.5): OIDC authentication client
- `tower-sessions` (0.14): Session management
- `askama` (0.12): Template engine
- `tokio`: Async runtime
- `rustls`: TLS implementation (via axum-server)
- `url`, `uuid`, `chrono`: Common utilities
- `serde`, `serde_json`: Serialization
