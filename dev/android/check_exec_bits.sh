#!/usr/bin/env bash
# Fail when a tracked file starts with a shebang but is not recorded executable.
#
# Why this exists: the build steps run `./dev/android/build_ash.sh` and
# `./gradlew`, and a non-executable file gives `exit 126 / Permission denied` on
# Linux. Windows checkouts do not carry the executable bit (core.fileMode is
# false there), so the problem is invisible from the machine that introduces it
# and only ever shows up in the release build. The mode is read from git — the
# one place that survives the checkout platform — while the shebang is read from
# the file itself.
#
# `git ls-files -s` prints "<mode> <sha> <stage>\t<path>".
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

bad=
while IFS=$'\t' read -r meta path; do
    mode=${meta%% *}
    case "$path" in *.ps1|*.bat|*.cmd) continue ;; esac   # run through an interpreter
    [ -f "$path" ] || continue
    [ "$(head -c 2 "$path")" = "#!" ] || continue
    [ "$mode" = "100755" ] || bad="$bad  $path ($mode)"$'\n'
done < <(git ls-files -s)

if [ -n "$bad" ]; then
    printf 'tracked files with a shebang but no executable bit:\n%s\n' "$bad" >&2
    printf 'fix with: git update-index --chmod=+x <path>\n' >&2
    exit 1
fi
echo "every shebang-tracked file is recorded executable"
