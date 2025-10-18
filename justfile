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
docker_build:
    docker buildx build \
        --load \
        --build-arg "GITHUB_SHA=$(git rev-parse HEAD)" \
        --build-arg "DESCRIPTION=$(./scripts/get_description.sh)" \
        --tag ghcr.io/yaleman/shorter:latest \
        .

# build and run the docker image, mounting ./config as the config dir
docker_run: docker_build
    docker run --rm -it \
        -p 9000:9000 \
        --mount type=bind,src=$(pwd)/config,target=/config \
        ghcr.io/yaleman/shorter:latest

run:
    cargo run --

run_debug:
    RUST_LOG=debug cargo run

# run mdbook in "serve" mode
serve_docs:
    cd docs && mdbook serve