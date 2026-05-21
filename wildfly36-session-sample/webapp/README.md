# WildFly 36 Seam session / core behavior sample

Minimal WAR plus Arquillian integration tests for Seam on **WildFly 36** (Jakarta EE): session context, conversation, bijection, Identity login, `@Restrict`, and JSF pages.

**Important:** the WAR includes `WEB-INF/classes/seam.properties`. Seam uses that file (even empty) to mark the archive for component scanning at bootstrap; without it, `@Name` components in the WAR may not install. This matches the official examples and booking IT deployments.

## Quick run

From the repo root:

```bash
./scripts/run-wildfly36-session-it.sh --install-parent   # first time only
./scripts/run-wildfly36-session-it.sh
```

Or after `source scripts/seam-dev-aliases.sh`: `seam-session-it`

## Manual browser testing

Build, deploy, and start WildFly in the **foreground** (server keeps running; URLs printed):

```bash
./scripts/run-wildfly36-session-manual.sh --install-parent   # first time only
./scripts/run-wildfly36-session-manual.sh
```

Open **http://127.0.0.1:8180/seam-session-wf36/** (port offset 100). Press Ctrl+C to stop the server.

Alias: `seam-session-manual` (after sourcing `scripts/seam-dev-aliases.sh`).

## Prerequisites

| Requirement | Location / notes |
|-------------|------------------|
| JDK 17 | `scripts/jdk17-env.sh` |
| Maven | Uses `~/.m2/repository` |
| WildFly 36.0.1.Final | `wildfly36/wildfly-36.0.1.Final` (gitignored; not committed) |
| Built `jboss-seam-jakarta` | `mvn install` from repo root or `--install-parent` on the script |

Tests use **port offset 100** (HTTP **8180**). Arquillian starts and stops the server.

## Manual Maven command

```bash
source scripts/jdk17-env.sh
cd wildfly36-session-sample
mvn clean verify -Darquillian=wildfly-local-36 -Dmaven.repo.local=$HOME/.m2/repository
```

Single test:

```bash
./scripts/run-wildfly36-session-it.sh --test SessionContextWildFly36IT#jsfLoginForm_postLogsInAndRedirectsToProtected
```

## What is tested

- Servlet probes: `/probe/*`, `/core/*`
- JSF: `home.xhtml`, `login.xhtml`, `protected.xhtml`, `admin.xhtml`, `conversation.xhtml`
- Failsafe: `SessionContextWildFly36IT` (25 tests)
