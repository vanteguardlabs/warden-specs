#!/bin/bash
set -euo pipefail

# Anchor to warden-specs root regardless of CWD.
cd "$(dirname "$0")/.."

MODE="patch"
while [ $# -gt 0 ]; do
    case "$1" in
        --major) MODE="major"; shift ;;
        --minor) MODE="minor"; shift ;;
        --patch) MODE="patch"; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -f VERSION ] || { echo "VERSION file missing" >&2; exit 1; }

old=$(tr -d '[:space:]' < VERSION)
case "$old" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "VERSION not semver (got '$old')" >&2; exit 1 ;;
esac

IFS='.' read -r major minor patch <<<"$old"
case "$MODE" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
esac
new="${major}.${minor}.${patch}"

# VERSION is the source of truth for "what version we're on". The
# served version per env lives in warden-e2e/<env>/version.json
# and is updated by that env's deploy.sh on a successful
# `compose up -d`. Bumping here doesn't change what visitors see
# until you actually deploy.
printf '%s\n' "$new" > VERSION

git add VERSION
git -c user.name=VanteguardLabs -c user.email=vanteguardlabs@gmail.com \
    commit -m "bump to ${new}"
git push origin main

echo "[VERSION] ${old} → ${new}"
