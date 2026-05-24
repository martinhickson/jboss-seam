#!/usr/bin/env bash
# Run Maven with Seam GitHub Packages repos + JBoss Public (mirrors CI settings).
# Credentials: GITHUB_TOKEN / GH_TOKEN, or github-packages server in ~/.m2/settings.xml
set -euo pipefail

JBOSS_PUBLIC_REPO="${JBOSS_PUBLIC_REPO:-https://repository.jboss.org/nexus/content/groups/public}"
EXTRA_REPO_RICHFACES="${EXTRA_REPO_RICHFACES:-https://maven.pkg.github.com/martinhickson/richfaces}"
EXTRA_REPO_RICHFACES_CORE="${EXTRA_REPO_RICHFACES_CORE:-https://maven.pkg.github.com/martinhickson/richfaces4-core}"
EXTRA_REPO_CDK="${EXTRA_REPO_CDK:-https://maven.pkg.github.com/martinhickson/richfaces-cdk}"
EXTRA_REPO_EL="${EXTRA_REPO_EL:-https://maven.pkg.github.com/martinhickson/jboss-el}"

USER_SETTINGS="${HOME}/.m2/settings.xml"
GITHUB_ACTOR="${GITHUB_ACTOR:-martinhickson}"
GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

if [[ -z "${GITHUB_TOKEN}" && -f "${USER_SETTINGS}" ]]; then
  GITHUB_TOKEN="$(xmllint --xpath 'string(//*[local-name()="server"][*[local-name()="id" and text()="github-packages"]]/*[local-name()="password"])' "${USER_SETTINGS}" 2>/dev/null || true)"
  GITHUB_ACTOR="$(xmllint --xpath 'string(//*[local-name()="server"][*[local-name()="id" and text()="github-packages"]]/*[local-name()="username"])' "${USER_SETTINGS}" 2>/dev/null || true)"
  GITHUB_ACTOR="${GITHUB_ACTOR:-martinhickson}"
fi

if [[ -z "${GITHUB_TOKEN}" ]]; then
  echo "GitHub Packages auth required. Set GITHUB_TOKEN, or add a github-packages server to ~/.m2/settings.xml" >&2
  exit 1
fi

SETTINGS_FILE="$(mktemp "${TMPDIR:-/tmp}/seam-settings.XXXXXX.xml")"
trap 'rm -f "${SETTINGS_FILE}"' EXIT

cat > "${SETTINGS_FILE}" <<EOF
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                              http://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers>
    <server>
      <id>github-packages</id>
      <username>${GITHUB_ACTOR}</username>
      <password>${GITHUB_TOKEN}</password>
    </server>
    <server>
      <id>github-packages-richfaces</id>
      <username>${GITHUB_ACTOR}</username>
      <password>${GITHUB_TOKEN}</password>
    </server>
    <server>
      <id>github-packages-richfaces-core</id>
      <username>${GITHUB_ACTOR}</username>
      <password>${GITHUB_TOKEN}</password>
    </server>
    <server>
      <id>github-packages-cdk</id>
      <username>${GITHUB_ACTOR}</username>
      <password>${GITHUB_TOKEN}</password>
    </server>
    <server>
      <id>github-packages-el</id>
      <username>${GITHUB_ACTOR}</username>
      <password>${GITHUB_TOKEN}</password>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>ci-extra-repositories</id>
      <repositories>
        <repository>
          <id>jboss-public</id>
          <name>JBoss Public Repository Group</name>
          <url>${JBOSS_PUBLIC_REPO}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>jboss-public</id>
          <name>JBoss Public Repository Group</name>
          <url>${JBOSS_PUBLIC_REPO}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>
    <profile>
      <id>bravura-extra-repos</id>
      <repositories>
        <repository>
          <id>github-packages-richfaces</id>
          <name>Bravura RichFaces (GitHub Packages)</name>
          <url>${EXTRA_REPO_RICHFACES}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
        <repository>
          <id>github-packages-richfaces-core</id>
          <name>Bravura RichFaces Core (GitHub Packages)</name>
          <url>${EXTRA_REPO_RICHFACES_CORE}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
        <repository>
          <id>github-packages-cdk</id>
          <name>Bravura RichFaces CDK (GitHub Packages)</name>
          <url>${EXTRA_REPO_CDK}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
        <repository>
          <id>github-packages-el</id>
          <name>Bravura JBoss EL (GitHub Packages)</name>
          <url>${EXTRA_REPO_EL}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>github-packages-richfaces</id>
          <name>Bravura RichFaces (GitHub Packages)</name>
          <url>${EXTRA_REPO_RICHFACES}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </pluginRepository>
        <pluginRepository>
          <id>github-packages-richfaces-core</id>
          <name>Bravura RichFaces Core (GitHub Packages)</name>
          <url>${EXTRA_REPO_RICHFACES_CORE}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </pluginRepository>
        <pluginRepository>
          <id>github-packages-cdk</id>
          <name>Bravura RichFaces CDK (GitHub Packages)</name>
          <url>${EXTRA_REPO_CDK}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </pluginRepository>
        <pluginRepository>
          <id>github-packages-el</id>
          <name>Bravura JBoss EL (GitHub Packages)</name>
          <url>${EXTRA_REPO_EL}</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>ci-extra-repositories</activeProfile>
    <activeProfile>bravura-extra-repos</activeProfile>
  </activeProfiles>
</settings>
EOF

exec mvn -s "${SETTINGS_FILE}" "$@"
