#!/usr/bin/env bash
# Build and run the Seam Booking demo (WildFly 36) with the UI tag gallery.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOKING_TESTS="${ROOT}/examples/booking/booking-tests"
MVN="${ROOT}/build/seam-mvn.sh"
JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
export JAVA_HOME
export MAVEN_OPTS="${MAVEN_OPTS:---add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED --add-opens=java.base/java.security=ALL-UNNAMED}"

WILDFLY_VERSION="${WILDFLY_VERSION:-36.0.0.Final}"
WILDFLY_HOME="${JBOSS_HOME:-${BOOKING_TESTS}/target/wildfly-${WILDFLY_VERSION}}"
HTTP_PORT="${BOOKING_HTTP_PORT:-8880}"
PORT_OFFSET="${BOOKING_PORT_OFFSET:-$((HTTP_PORT - 8080))}"
DEMO_WAR="${BOOKING_TESTS}/target/seam-booking-demo.war"
CONTEXT_PATH="/seam-booking"
PID_FILE="${BOOKING_TESTS}/target/booking-demo.pid"
LOG_FILE="${BOOKING_TESTS}/target/booking-demo.log"

usage() {
  cat <<EOF
Usage: $(basename "$0") [start|stop|status|build]

  start   Build the demo WAR (if needed), deploy to WildFly, and keep the server running
  stop    Stop the demo WildFly process started by this script
  status  Show whether the demo server responds
  build   Build/export the demo WAR only

Environment:
  JAVA_HOME          JDK 17+ (default: ${JAVA_HOME})
  JBOSS_HOME         WildFly install (default: ${WILDFLY_HOME})
  BOOKING_HTTP_PORT  HTTP port (default: ${HTTP_PORT})

URLs when running:
  http://127.0.0.1:${HTTP_PORT}${CONTEXT_PATH}/home.seam
  http://127.0.0.1:${HTTP_PORT}${CONTEXT_PATH}/seam-ui-showcase.seam
EOF
}

wait_for_http() {
  local url="$1"
  local attempts="${2:-90}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

build_demo_war() {
  echo "==> Building Seam core modules and booking demo WAR..."
  "${MVN}" -f "${ROOT}/pom.xml" -pl jboss-seam-jakarta,jboss-seam-ui-jakarta -am -ntp install -DskipTests
  (cd "${BOOKING_TESTS}" && "${MVN}" -ntp test-compile exec:java -Dexec.classpathScope=test)
  [[ -f "${DEMO_WAR}" ]] || { echo "Demo WAR not found at ${DEMO_WAR}" >&2; exit 1; }
  echo "==> Demo WAR ready: ${DEMO_WAR}"
}

ensure_wildfly() {
  if [[ ! -d "${WILDFLY_HOME}" ]]; then
    echo "==> Downloading WildFly ${WILDFLY_VERSION}..."
    (cd "${BOOKING_TESTS}" && "${MVN}" -ntp process-test-classes -Pwildfly-managed)
  fi
  [[ -x "${WILDFLY_HOME}/bin/standalone.sh" ]] || {
    echo "WildFly not found at ${WILDFLY_HOME}" >&2
    exit 1
  }
}

stop_demo() {
  local deploy_dir="${WILDFLY_HOME}/standalone/deployments"
  if [[ -d "${deploy_dir}" ]]; then
    rm -f "${deploy_dir}/seam-booking-demo.war" \
          "${deploy_dir}/seam-booking-demo.war.failed" \
          "${deploy_dir}/seam-booking-demo.war.deployed" \
          "${deploy_dir}/seam-booking-demo.war.dodeploy" \
          "${deploy_dir}/seam-booking-demo.war.isdeploying"
  fi
  if [[ -f "${PID_FILE}" ]]; then
    local pid
    pid="$(cat "${PID_FILE}")"
    if kill -0 "${pid}" 2>/dev/null; then
      echo "==> Stopping WildFly (pid ${pid})..."
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
    rm -f "${PID_FILE}"
  fi
  pkill -f "${WILDFLY_HOME}/bin/standalone.sh" 2>/dev/null || true
  pkill -f "${WILDFLY_HOME}/jboss-modules.jar" 2>/dev/null || true
  sleep 2
}

deploy_war() {
  local deploy_dir="${WILDFLY_HOME}/standalone/deployments"
  mkdir -p "${deploy_dir}"
  rm -f "${deploy_dir}/seam-booking-demo.war" "${deploy_dir}/seam-booking-demo.war.failed" "${deploy_dir}/seam-booking-demo.war.deployed"
  cp "${DEMO_WAR}" "${deploy_dir}/seam-booking-demo.war"
  touch "${deploy_dir}/seam-booking-demo.war.dodeploy"
}

start_demo() {
  if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    echo "Demo already running (pid $(cat "${PID_FILE}"))."
    exit 0
  fi

  build_demo_war
  ensure_wildfly
  stop_demo

  echo "==> Starting WildFly (HTTP port ${HTTP_PORT}, offset ${PORT_OFFSET})..."
  export JBOSS_HOME="${WILDFLY_HOME}"
  deploy_war

  nohup "${WILDFLY_HOME}/bin/standalone.sh" \
    -Djboss.bind.address=127.0.0.1 \
    -Djboss.socket.binding.port-offset="${PORT_OFFSET}" \
    >> "${LOG_FILE}" 2>&1 &
  echo $! > "${PID_FILE}"

  local home_url="http://127.0.0.1:${HTTP_PORT}${CONTEXT_PATH}/home.seam"
  local gallery_url="http://127.0.0.1:${HTTP_PORT}${CONTEXT_PATH}/seam-ui-showcase.seam"

  echo "==> Waiting for deployment (log: ${LOG_FILE})..."
  if wait_for_http "${home_url}"; then
    echo
    echo "Seam Booking demo is running."
    echo "  Login / booking:  ${home_url}"
    echo "  UI tag gallery:   ${gallery_url}"
    echo "  Demo accounts:    demo/demo  or  gavin/foobar"
    echo
    echo "Tail logs: tail -f ${LOG_FILE}"
    echo "Stop:      $(basename "$0") stop"
  else
    echo "Server did not become ready in time. Check ${LOG_FILE}" >&2
    exit 1
  fi
}

status_demo() {
  local home_url="http://127.0.0.1:${HTTP_PORT}${CONTEXT_PATH}/home.seam"
  local gallery_url="http://127.0.0.1:${HTTP_PORT}${CONTEXT_PATH}/seam-ui-showcase.seam"
  if curl -fsS -o /dev/null "${home_url}" 2>/dev/null; then
    echo "running"
    echo "  ${home_url}"
    echo "  ${gallery_url}"
  else
    echo "not running"
    exit 1
  fi
}

cmd="${1:-start}"
case "${cmd}" in
  start) start_demo ;;
  stop) stop_demo ;;
  status) status_demo ;;
  build) build_demo_war ;;
  -h|--help|help) usage ;;
  *) usage; exit 1 ;;
esac
