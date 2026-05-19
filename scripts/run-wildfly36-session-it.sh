#!/usr/bin/env bash
# Run WildFly 36 Arquillian integration tests for wildfly36-session-sample.
#
# Usage:
#   ./scripts/run-wildfly36-session-it.sh
#   ./scripts/run-wildfly36-session-it.sh --install-parent
#   ./scripts/run-wildfly36-session-it.sh --test SessionContextWildFly36IT#jsfLoginForm_postLogsInAndRedirectsToProtected
#
# Prerequisites:
#   - JDK 17
#   - Maven
#   - WildFly 36 at wildfly36/wildfly-36.0.1.Final (port offset 100 → HTTP 8180)
#   - jboss-seam-jakarta installed to local ~/.m2 (use --install-parent once)

set -euo pipefail

SEAM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE_DIR="${SEAM_ROOT}/wildfly36-session-sample"
WILDFLY_HOME="${WILDFLY36_HOME:-${SEAM_ROOT}/wildfly36/wildfly-36.0.1.Final}"
M2_LOCAL="${SEAM_M2_REPO:-${HOME}/.m2/repository}"
INSTALL_PARENT=0
MVN_EXTRA=()
IT_TEST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-parent)
      INSTALL_PARENT=1
      shift
      ;;
    --test)
      IT_TEST="$2"
      shift 2
      ;;
    -q|--quiet)
      MVN_EXTRA+=(-q)
      shift
      ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# shellcheck source=/dev/null
source "${SEAM_ROOT}/scripts/jdk17-env.sh"
export JDK17_ENV_QUIET=1

if [[ ! -x "${WILDFLY_HOME}/bin/standalone.sh" ]]; then
  echo "error: WildFly not found at ${WILDFLY_HOME}" >&2
  echo "  Extract WildFly 36.0.1.Final to wildfly36/wildfly-36.0.1.Final or set WILDFLY36_HOME." >&2
  exit 1
fi

if [[ ! -d "${SAMPLE_DIR}" ]]; then
  echo "error: sample module missing at ${SAMPLE_DIR}" >&2
  exit 1
fi

if [[ "${INSTALL_PARENT}" -eq 1 ]]; then
  echo "==> Installing Seam parent + jakarta module into local Maven repo"
  (cd "${SEAM_ROOT}" && mvn -q install -pl bom,jboss-seam-jakarta -am \
    -Dmaven.repo.local="${M2_LOCAL}" -DskipTests)
fi

if ! ls "${M2_LOCAL}/org/jboss/seam/jboss-seam-jakarta"/*/jboss-seam-jakarta-*.jar &>/dev/null; then
  echo "warning: jboss-seam-jakarta not found in ${M2_LOCAL}" >&2
  echo "  Run: $0 --install-parent" >&2
fi

echo "==> Running wildfly36-session-sample ITs (WildFly managed, port offset 100)"
echo "    JAVA_HOME=${JAVA_HOME}"
echo "    WILDFLY_HOME=${WILDFLY_HOME}"
echo "    M2=${M2_LOCAL}"

cd "${SAMPLE_DIR}"

MVN_ARGS=(
  clean
  verify
  -Darquillian=wildfly-local-36
  -Dmaven.repo.local="${M2_LOCAL}"
)

if [[ -n "${IT_TEST}" ]]; then
  MVN_ARGS+=("-Dit.test=${IT_TEST}")
fi

mvn "${MVN_EXTRA[@]}" "${MVN_ARGS[@]}"

echo "==> Done. 25 integration tests expected on success (Failsafe)."
