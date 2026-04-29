#!/usr/bin/env bash
# Patch B — Week 4 follow-up.
#
# Fixes the import paths in internal/crypto/*_test.go to match the actual
# go.mod module declaration (`module upspa`). Before this patch the test
# files referenced two stale module paths that never matched go.mod:
#
#   - "github.com/your-org/sp/internal/crypto"                              (template placeholder)
#   - "github.com/rezasaadi/UpSPA_FPB/services/storage-provider-go/...      (planned path that was never set in go.mod)
#
# Result of the mismatch: `go test ./internal/crypto/...` fails to build
# before any test runs. After this patch all *_test.go files import
# "upspa/internal/crypto", matching go.mod.
#
# Run from services/storage-provider-go/.

set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -f go.mod ]] || ! grep -q '^module upspa$' go.mod; then
  echo "ERROR: run this from services/storage-provider-go/ (where go.mod lives)" >&2
  exit 1
fi

FILES=(
  internal/crypto/b64_test.go
  internal/crypto/ed25519_test.go
  internal/crypto/pwd_update_sigmsg_test.go
  internal/crypto/scalar_keygen_test.go
  internal/crypto/fuzz_test.go
  internal/crypto/negative_test.go
  internal/crypto/ristretto_test.go
)

for f in "${FILES[@]}"; do
  if [[ -f "$f" ]]; then
    # Both legacy paths → "upspa/internal/crypto"
    sed -i \
      -e 's#github.com/your-org/sp/internal/crypto#upspa/internal/crypto#g' \
      -e 's#github.com/rezasaadi/UpSPA_FPB/services/storage-provider-go/internal/crypto#upspa/internal/crypto#g' \
      "$f"
    echo "patched: $f"
  fi
done

echo
echo "Done. Verifying tests build:"
go vet ./internal/crypto/... && echo "  go vet OK"
echo "Run: go test ./internal/crypto/..."
