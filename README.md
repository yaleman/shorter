Shorter
=======

URL shortener service in Rust (Axum + SeaORM + SQLite) with optional OIDC auth.

Features

- SQLite-backed short links
- Optional public/private admin UI
- Docker image build via reusable GitHub workflow (`docker/github-builder`)

Quick start

- Install Rust
- `cargo run`
- Open:
  - Admin: `https://127.0.0.1:9000/admin/`
  - Redirect: `https://127.0.0.1:9000/{tag}`

Environment

- `SHORTER_LISTENER_ADDR` (default: `127.0.0.1:9000`)
- `SHORTER_FRONTEND_URL` (required, no trailing slash)
- `SHORTER_TLS_CERT` (required)
- `SHORTER_TLS_KEY` (required)
- `SHORTER_OIDC_DISCOVERY_URL` (optional)
- `SHORTER_OIDC_CLIENT_ID` (optional)

OIDC behavior

- If OIDC env vars are set, admin routes require login.
- Without them, admin runs in public mode.

Local scripts

- `cargo run`
- `cargo test`
- `cargo clippy`
- `cargo fmt`
- `just check` (clippy + test + fmt)

Docker

- Build image (local helper): `just docker_build`
- CI builds and pushes to `ghcr.io/<owner>/<repo>` for:
  - `main` branch pushes
  - tags and pull requests generate tags but no push
