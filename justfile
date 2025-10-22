git := require("git")
cargo := require("cargo")
pnpm := require("pnpm")
npx := require("npx")

default:
    just --list

# run the linter, tests, and format the code
check: clippy test fmt

# run clippy
clippy:
    cargo clippy --all-targets --quiet --workspace

# run rust tests
test:
    cargo test --quiet --workspace

# format the rust code
fmt:
    cargo fmt --all -- --check


# run shellcheck on scripts
lint-scripts:
    shellcheck *.sh
    shellcheck scripts/*.sh


# lint JavaScript and CSS files
lint-web:
    pnpm run lint

set positional-arguments

@coverage_inner *args='':
    cargo tarpaulin --workspace --exclude-files=src/main.rs $@

# run coverage checks
coverage:
    just coverage_inner --out=Html
    @echo "Coverage report should be at file://$(pwd)/tarpaulin-report.html"

coveralls:
    just coverage_inner --out=Html --coveralls $COVERALLS_REPO_TOKEN
    @echo "Coverage report should be at https://coveralls.io/github/yaleman/shorter?branch=$(git branch --show-current)"

# build the docker image
@docker_build *args='':
    docker buildx build \
        --load \
        --build-arg "GITHUB_SHA=$(git rev-parse HEAD)" \
        --platform linux/$(uname -m) \
        --tag ghcr.io/yaleman/shorter:latest $@ \
        .

# build and run the docker image, mounting ./config as the config dir
docker_run: docker_build
    docker run --rm -it \
        -p 9000:9000 \
        --platform linux/$(uname -m) \
        --env "SHORTER_TLS_CERT=${SHORTER_TLS_CERT}" \
        --env "SHORTER_TLS_KEY=${SHORTER_TLS_KEY}" \
        --env "SHORTER_FRONTEND_URL=${SHORTER_FRONTEND_URL}" \
        --env "SHORTER_OIDC_CLIENT_ID=${SHORTER_OIDC_CLIENT_ID}" \
        --env "SHORTER_OIDC_DISCOVERY_URL=${SHORTER_OIDC_DISCOVERY_URL}" \
        --env "SHORTER_LISTENER_ADDRESS=${SHORTER_LISTENER_ADDRESS}" \
        --mount type=bind,src=$(pwd),target=/data/ \
        ghcr.io/yaleman/shorter:latest

run:
    cargo run --

run_debug:
    RUST_LOG=debug cargo run

# run mdbook in "serve" mode
serve_docs:
    cd docs && mdbook serve

@semgrep *args='':
    semgrep ci --config auto \
    --exclude-rule "yaml.github-actions.security.third-party-action-not-pinned-to-commit-sha.third-party-action-not-pinned-to-commit-sha" $@