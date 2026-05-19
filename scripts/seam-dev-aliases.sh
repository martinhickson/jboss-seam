#!/usr/bin/env bash
# From the repo root (any clone location):
#   source scripts/seam-dev-aliases.sh
# Or from ~/.bashrc using your clone path, e.g.:
#   source "$HOME/work/jboss-seam/scripts/seam-dev-aliases.sh"

_SEAM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

alias jdk17="source ${_SEAM_ROOT}/scripts/jdk17-env.sh"
alias seam-build='jdk17 && cd "${_SEAM_ROOT}" && mvn -Dmaven.repo.local="${HOME}/.m2/repository"'
alias seam-session-it='"${_SEAM_ROOT}/scripts/run-wildfly36-session-it.sh"'
alias seam-session-manual='"${_SEAM_ROOT}/scripts/run-wildfly36-session-manual.sh"'

export SEAM_ROOT="${_SEAM_ROOT}"
export WILDFLY36_HOME="${_SEAM_ROOT}/wildfly36/wildfly-36.0.1.Final"
