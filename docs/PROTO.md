# Protobuf regeneration

The master/worker gRPC contract lives in
[`internal/dist/proto/coordinator.proto`](../internal/dist/proto/coordinator.proto).
The Go files beside it (`coordinator.pb.go`, `coordinator_grpc.pb.go`) are
**generated**. Never hand-edit them: edit the `.proto`, regenerate, and commit
both the source and the generated output in the same change.

## Pinned toolchain

Reproducibility matters here. `protoc-gen-go` writes the generator and compiler
versions into the generated header, so an unpinned toolchain turns every
regeneration into a diff unrelated to the schema. The versions are pinned in
[`scripts/gen-proto.sh`](../scripts/gen-proto.sh) and checked by CI:

| Tool | Version |
| --- | --- |
| `protoc` | 36.0 (generated header: `protoc v7.36.0`) |
| `protoc-gen-go` | v1.36.12 |
| `protoc-gen-go-grpc` | v1.6.2 |
| Go | 1.26.11 (from `go.mod` / CI) |

Install them locally:

```bash
# macOS
brew install protobuf@36            # protoc 36.0

# Linux (x86_64)
curl -fsSL -o /tmp/protoc.zip \
  https://github.com/protocolbuffers/protobuf/releases/download/v36.0/protoc-36.0-linux-x86_64.zip
unzip -o /tmp/protoc.zip -d /usr/local

go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
```

Make sure `$(go env GOPATH)/bin` is on `PATH`. The script refuses to run when a
version differs, rather than silently generating code with a different
toolchain.

## Regenerate

From the repository root:

```bash
make proto
# equivalent:
go generate ./internal/dist/proto
# also equivalent:
bash scripts/gen-proto.sh
```

`go generate` only scans `.go` files, so the executable directive is in
[`internal/dist/proto/generate.go`](../internal/dist/proto/generate.go); the
same directive is recorded as a comment in the `.proto` for readers there. All
three entry points call the same script.

The script runs protoc from the repository root with `paths=source_relative`,
which preserves the `source: internal/dist/proto/coordinator.proto` header in
the generated files.

## Verify

```bash
make proto
git diff --exit-code -- internal/dist/proto/   # must be empty
go test ./internal/dist/proto/... -count=1
```

CI runs exactly these steps in
[`.github/workflows/proto-check.yml`](../.github/workflows/proto-check.yml),
installing the pinned `protoc` and plugins first. A schema change that lands
without regenerated Go code fails that workflow.
