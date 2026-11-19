#!/usr/bin/env bash
# Regenerate the distributed coordinator's protobuf Go code.
#
# The versions are pinned on purpose: protoc-gen-go embeds the generator and
# compiler versions in the generated header, so an unpinned toolchain makes
# every run produce a spurious diff. `make proto`, `go generate ./internal/dist/proto`
# and .github/workflows/proto-check.yml all call this one script.
set -euo pipefail

readonly PROTOC_VERSION="36.0"                 # libprotoc 36.0 -> header "protoc v7.36.0"
readonly PROTOC_GEN_GO_VERSION="v1.36.12"
readonly PROTOC_GEN_GO_GRPC_VERSION="v1.6.2"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() {
	echo "gen-proto: $*" >&2
	exit 1
}

for tool in protoc protoc-gen-go protoc-gen-go-grpc; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is not on PATH; install the pinned versions in docs/PROTO.md"
done

protoc_version="$(protoc --version)" # e.g. "libprotoc 36.0"
[[ "$protoc_version" == *"$PROTOC_VERSION"* ]] ||
	fail "expected protoc $PROTOC_VERSION, got '$protoc_version'"

go_version="$(protoc-gen-go --version 2>&1)" # e.g. "protoc-gen-go v1.36.12"
[[ "$go_version" == *"${PROTOC_GEN_GO_VERSION#v}"* ]] ||
	fail "expected protoc-gen-go $PROTOC_GEN_GO_VERSION, got '$go_version'"

grpc_version="$(protoc-gen-go-grpc --version 2>&1)" # e.g. "protoc-gen-go-grpc 1.6.2"
[[ "$grpc_version" == *"${PROTOC_GEN_GO_GRPC_VERSION#v}"* ]] ||
	fail "expected protoc-gen-go-grpc $PROTOC_GEN_GO_GRPC_VERSION, got '$grpc_version'"

# paths=source_relative writes next to the .proto, keeping the generated files
# in internal/dist/proto with the header `source: internal/dist/proto/...`.
protoc \
	--go_out=. --go_opt=paths=source_relative \
	--go-grpc_out=. --go-grpc_opt=paths=source_relative \
	internal/dist/proto/coordinator.proto

echo "gen-proto: regenerated internal/dist/proto/coordinator.pb.go and coordinator_grpc.pb.go"
