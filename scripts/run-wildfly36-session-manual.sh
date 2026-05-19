#!/usr/bin/env bash
# Build and run wildfly36-session-sample on local WildFly 36 for manual browser testing.
# The server stays in the foreground until you press Ctrl+C.
#
# Usage:
#   ./scripts/run-wildfly36-session-manual.sh
#   ./scripts/run-wildfly36-session-manual.sh --install-parent
#   ./scripts/run-wildfly36-session-manual.sh --no-build   # reuse existing WAR
#
# Prerequisites: same as run-wildfly36-session-it.sh (JDK 17, WildFly 36, local m2).

set -euo pipefail

SEAM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE_DIR="${SEAM_ROOT}/wildfly36-session-sample"
WILDFLY_HOME="${WILDFLY36_HOME:-${SEAM_ROOT}/wildfly36/wildfly-36.0.1.Final}"
M2_LOCAL="${SEAM_M2_REPO:-${HOME}/.m2/repository}"
WAR_NAME="seam-session-wf36.war"
CONTEXT="seam-session-wf36"
PORT_OFFSET=100
HTTP_PORT=8080
HTTP_PORT=$((HTTP_PORT + PORT_OFFSET))
BASE_URL="http://127.0.0.1:${HTTP_PORT}/${CONTEXT}"

INSTALL_PARENT=0
DO_BUILD=1
MVN_EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-parent)
      INSTALL_PARENT=1
      shift
      ;;
    --no-build)
      DO_BUILD=0
      shift
      ;;
    -q|--quiet)
      MVN_EXTRA+=(-q)
      shift
      ;;
    -h|--help)
      sed -n '2,18p' "$0"
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

if [[ "${INSTALL_PARENT}" -eq 1 ]]; then
  echo "==> Installing Seam parent + jakarta module into local Maven repo"
  (cd "${SEAM_ROOT}" && mvn -q install -pl bom,jboss-seam-jakarta -am \
    -Dmaven.repo.local="${M2_LOCAL}" -DskipTests)
fi

WAR="${SAMPLE_DIR}/target/${WAR_NAME}"

if [[ "${DO_BUILD}" -eq 1 ]]; then
  echo "==> Building ${WAR_NAME}"
  (cd "${SAMPLE_DIR}" && mvn "${MVN_EXTRA[@]}" package -DskipTests \
    -Dmaven.repo.local="${M2_LOCAL}")
fi

if [[ ! -f "${WAR}" ]]; then
  echo "error: WAR not found at ${WAR}" >&2
  exit 1
fi

DEPLOY_DIR="${WILDFLY_HOME}/standalone/deployments"
rm -f "${DEPLOY_DIR}/${CONTEXT}.war"* "${DEPLOY_DIR}/seam-session-wf36"*.war* 2>/dev/null || true
cp -f "${WAR}" "${DEPLOY_DIR}/"

if command -v ss >/dev/null 2>&1 && ss -ltn | grep -q ":${HTTP_PORT} "; then
  echo "warning: port ${HTTP_PORT} is already in use; stop the other process or change PORT_OFFSET in this script" >&2
fi

print_urls() {
  cat <<EOF

================================================================================
  Seam session sample — manual testing (WildFly 36, port offset ${PORT_OFFSET})
================================================================================
  Base URL:  ${BASE_URL}/

  JSF pages
    Home:         ${BASE_URL}/home.xhtml
    Login:        ${BASE_URL}/login.xhtml
    Protected:    ${BASE_URL}/protected.xhtml
    Admin:        ${BASE_URL}/admin.xhtml
    Conversation: ${BASE_URL}/conversation.xhtml

  Servlet probes
    Session:      ${BASE_URL}/probe/servlet
    Raw (no ctx): ${BASE_URL}/probe/raw
    Identity:     ${BASE_URL}/core/identity/status
    Login probe:  ${BASE_URL}/core/identity/login?username=demo&password=secret

  Test users (SampleAuthenticator)
    demo / secret  — roles user, admin
    guest / guest  — role user only

  Press Ctrl+C to stop WildFly.
================================================================================

EOF
}

print_urls

echo "==> Starting WildFly (foreground) — ${WILDFLY_HOME}"
echo "    JAVA_HOME=${JAVA_HOME}"

cd "${WILDFLY_HOME}"
exec ./bin/standalone.sh \
  -Djboss.bind.address=127.0.0.1 \
  -Djboss.socket.binding.port-offset="${PORT_OFFSET}" \
  -Djboss.deployment.scanner.enabled=false
