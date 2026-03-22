set -euo pipefail
branch="$(git rev-parse --abbrev-ref HEAD)"

allowed=()

case "$branch" in
  intern/efe)
    allowed+=("services/storage-provider-go/internal/crypto/")
    allowed+=("services/storage-provider-go/INTERN_NOTES/efe-")
    ;;
  intern/sina)
    allowed+=("services/storage-provider-go/internal/db/")
    allowed+=("services/storage-provider-go/internal/testutil/")
    allowed+=("services/storage-provider-go/INTERN_NOTES/sina-")
    ;;
  intern/emirhan)
    allowed+=("services/storage-provider-go/internal/api/")
    allowed+=("services/storage-provider-go/internal/config/")
    allowed+=("services/storage-provider-go/internal/model/")
    allowed+=("services/storage-provider-go/cmd/sp/")
    allowed+=("services/storage-provider-go/INTERN_NOTES/emirhan-")
    ;;
  intern/extension)
    allowed+=("packages/extension/")
    allowed+=("packages/upspa-js/")
    ;;
  Feyza)
    allowed+=("packages/extension/")
    allowed+=("packages/upspa-js/")
    ;;
  *)
    exit 0
    ;;
esac
mapfile -t files < <(git diff --cached --name-only --diff-filter=ACMR)
mapfile -t deleted < <(git diff --cached --name-only --diff-filter=D)
if (( ${#deleted[@]} > 0 )); then
  echo "Deletions are not allowed on intern branches."
  echo "   Deleted files staged:"
  printf '   - %s\n' "${deleted[@]}"
  exit 1
fi

violations=()

is_allowed() {
  local f="$1"
  for p in "${allowed[@]}"; do
    if [[ "$f" == "$p"* ]]; then
      return 0
    fi
  done
  return 1
}

for f in "${files[@]}"; do
  if ! is_allowed "$f"; then
    violations+=("$f")
  fi
done

if (( ${#violations[@]} > 0 )); then
  echo "Commit blocked on branch '$branch'."
  echo "You can only modify files under:"
  printf '  - %s\n' "${allowed[@]}"
  echo ""
  echo "Files staged outside your allowed scope:"
  printf '  - %s\n' "${violations[@]}"
  echo ""
  echo "Fix: unstage those files (git restore --staged <file>) or revert changes."
  exit 1
fi

exit 0