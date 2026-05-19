#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=jdk17-env.sh
source "${SCRIPT_DIR}/jdk17-env.sh"
export JDK17_ENV_QUIET=1

exec mvn -Dmaven.repo.local="${HOME}/.m2/repository" "$@"
