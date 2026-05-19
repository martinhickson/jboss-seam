#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WF_HOME="${WILDFLY36_HOME:-${ROOT}/wildfly36/wildfly-36.0.1.Final}"
WAR="${ROOT}/wildfly36-session-sample/target/seam-session-wf36.war"

source "${ROOT}/scripts/jdk17-env.sh"
export JDK17_ENV_QUIET=1

cd "${ROOT}/wildfly36-session-sample"
mvn -q package -DskipTests -Dmaven.repo.local="${HOME}/.m2/repository"

if [[ ! -d "${WF_HOME}" ]]; then
  echo "WildFly not found at ${WF_HOME}" >&2
  exit 1
fi

cp -f "${WAR}" "${WF_HOME}/standalone/deployments/"
echo "Deployed ${WAR}"
echo "For build + start + URLs, prefer: ${ROOT}/scripts/run-wildfly36-session-manual.sh"
echo "Or start server with port offset 100:"
echo "  ${WF_HOME}/bin/standalone.sh -Djboss.socket.binding.port-offset=100"
echo "Then open: http://127.0.0.1:8180/seam-session-wf36/home.xhtml"
