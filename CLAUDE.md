# weka-log-collector — Developer Instructions

## Before Every Commit: Run All Quality Checks

    cd /Users/manmeet.singh/weka_log_collector
    task check

This runs in order: fmt -> vet -> lint -> test -> build.
**Do not commit if any step fails.**

## Individual Tasks

| Command         | What it does                                          |
|-----------------|-------------------------------------------------------|
| `task fmt`      | Format code with gofmt (modifies files)               |
| `task vet`      | Static analysis (go vet)                              |
| `task lint`     | Linter (staticcheck)                                  |
| `task test`     | Unit tests (go test ./... -v)                         |
| `task build`    | Compile binary for current platform                   |
| `task build-linux` | Cross-compile static Linux binary for Weka nodes  |
| `task check`    | All of the above, in order                            |

## One-Time Setup

Install the task runner:

    go install github.com/go-task/task/v3/cmd/task@latest

Install staticcheck:

    go install honnef.co/go/tools/cmd/staticcheck@latest

## Building a Linux binary (for deployment to Weka nodes)

    task build-linux
    # produces: weka-log-collector_linux_amd64

Copy to a Weka node and run:

    scp weka-log-collector_linux_amd64 root@<node>:/tmp/weka-log-collector

## Code Layout

- `main.go`       — all implementation (single file)
- `main_test.go`  — all unit tests
- `go.mod`        — Go module definition (no external dependencies)

## Rules

- NEVER commit without running `task check` first
- Fix ALL fmt, vet, lint, and test failures before committing
- No external dependencies — stdlib only
- No CGo
- Binary must build statically for Linux amd64 via `task build-linux`
