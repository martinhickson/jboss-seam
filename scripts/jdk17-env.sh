#!/usr/bin/env bash
# Source this file to use JDK 17 for Seam / WildFly 36 builds.
# Usage: source scripts/jdk17-env.sh   OR   alias jdk17='source .../jdk17-env.sh'

if [[ -d /usr/lib/jvm/java-17-openjdk-amd64 ]]; then
  export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
elif [[ -d /usr/lib/jvm/java-1.17.0-openjdk-amd64 ]]; then
  export JAVA_HOME=/usr/lib/jvm/java-1.17.0-openjdk-amd64
else
  echo "jdk17-env: JDK 17 not found under /usr/lib/jvm" >&2
  return 1 2>/dev/null || exit 1
fi

export PATH="$JAVA_HOME/bin:$PATH"

# Prefer user-local Maven repository when building Seam
export MAVEN_OPTS="${MAVEN_OPTS:-}"
export SEAM_M2_REPO="${SEAM_M2_REPO:-$HOME/.m2/repository}"

if [[ "${JDK17_ENV_QUIET:-}" != "1" ]]; then
  echo "JAVA_HOME=$JAVA_HOME"
  java -version 2>&1 | head -1
fi
