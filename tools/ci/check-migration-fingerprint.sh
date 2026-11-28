#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
expected=$(cd -- "$repo/internal/store" && sha256sum migrations/*.sql | sha256sum)
actual=$(docker run --rm --network none "$1" account huella-migraciones)
[[ "$actual" == "${expected%% *}" ]]
