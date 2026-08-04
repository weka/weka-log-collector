# weka-log-collector — Developer Instructions

## Before Every Commit: Run All Quality Checks

    task check

This runs in order: fmt -> vet -> lint -> test -> build -> build-linux -> build-linux-arm64.
**Do not commit if any step fails.**

## Individual Tasks

| Command                  | What it does                                          |
|--------------------------|-------------------------------------------------------|
| `task fmt`               | Format code with gofmt (modifies files)               |
| `task vet`               | Static analysis (go vet)                              |
| `task lint`              | Linter (staticcheck)                                  |
| `task test`              | Unit tests (go test ./... -v)                         |
| `task build`             | Compile binary for current platform (macOS)           |
| `task build-linux`       | Cross-compile static Linux binary (amd64)             |
| `task build-linux-arm64` | Cross-compile static Linux binary (arm64)             |
| `task check`             | All of the above, in order                            |

## One-Time Setup

Install the task runner:

    go install github.com/go-task/task/v3/cmd/task@latest

Install staticcheck:

    go install honnef.co/go/tools/cmd/staticcheck@latest

Install git hooks (builds and stages the Linux binary on every commit):

    task install-hooks

## Deploying to Weka nodes

Both Linux binaries are committed to the repo. Nodes update with:

    git pull

No build step needed on the node — the binaries are always up to date in git.

| Binary                    | Architecture         | Nodes               |
|---------------------------|----------------------|---------------------|
| `weka-log-collector`      | Linux amd64 (x86_64) | Standard Weka nodes |
| `weka-log-collector-arm64`| Linux arm64 (aarch64)| ARM nodes (aarch64) |

## Code Layout

- `main.go`       — all implementation (single file)
- `main_test.go`  — all unit tests
- `go.mod`        — Go module definition (no external dependencies)

## Rules

- NEVER commit without running `task check` first
- Fix ALL fmt, vet, lint, and test failures before committing
- ALWAYS stage and commit BOTH binaries alongside code changes (`git add weka-log-collector weka-log-collector-arm64`)
- No external dependencies — stdlib only
- No CGo
- Both binaries must build statically via `task build-linux` (amd64) and `task build-linux-arm64` (arm64)
