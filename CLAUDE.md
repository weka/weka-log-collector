# weka-log-collector — Developer Instructions

## Before Every Commit: Run All Quality Checks

    task check

This runs in order: fmt -> vet -> lint -> test -> build -> build-linux.
**Do not commit if any step fails.**

## Individual Tasks

| Command            | What it does                                          |
|--------------------|-------------------------------------------------------|
| `task fmt`         | Format code with gofmt (modifies files)               |
| `task vet`         | Static analysis (go vet)                              |
| `task lint`        | Linter (staticcheck)                                  |
| `task test`        | Unit tests (go test ./... -v)                         |
| `task build`       | Compile binary for current platform (macOS)           |
| `task build-linux` | Cross-compile static Linux binary                     |
| `task check`       | All of the above, in order                            |

## One-Time Setup

Install the task runner:

    go install github.com/go-task/task/v3/cmd/task@latest

Install staticcheck:

    go install honnef.co/go/tools/cmd/staticcheck@latest

## Deploying to Weka nodes

The compiled Linux binary is committed to the repo. Backend nodes update with:

    git pull

No build step needed on the node — the binary is always up to date in git.

## Code Layout

- `main.go`       — all implementation (single file)
- `main_test.go`  — all unit tests
- `go.mod`        — Go module definition (no external dependencies)

## Rules

- NEVER commit without running `task check` first
- Fix ALL fmt, vet, lint, and test failures before committing
- ALWAYS stage and commit the `weka-log-collector` binary alongside code changes (`git add weka-log-collector`)
- No external dependencies — stdlib only
- No CGo
- Binary must build statically for Linux amd64 via `task build-linux`
