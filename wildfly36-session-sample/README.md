# WildFly 36 Seam session / core behavior sample

Minimal WAR plus Arquillian integration tests for Seam on **WildFly 36** (Jakarta EE): session context, conversation, bijection, Identity login, `@Restrict`, JSF pages, and **`WEB-INF/lib` JAR scanning**.

## Modules

| Module | Role |
|--------|------|
| `enhanced-seam-lib/` | JAR overriding `@Name("org.jboss.seam.web.session")` → packaged in `WEB-INF/lib` |
| `webapp/` | WAR (`seam-session-wf36.war`) + Failsafe ITs |

## Seam archive markers (WAR and lib JAR)

On Jakarta Seam, **each archive** that contains `@Name` components needs:

1. **`seam.properties`** at the JAR/WAR classpath root (`WEB-INF/classes/seam.properties` in the WAR; root of a lib JAR)
2. **`META-INF/jandex.idx`** — built by `jandex-maven-plugin` (Jakarta mode does not scan `.class` files on disk)

Without (1), the archive is **ignored**. With (1) but without (2), bootstrap **throws** (`IllegalStateException: Jakarta Seam requires META-INF/jandex.idx …`).

`EnhancedSeamSession` extends `org.jboss.seam.web.Session` and uses the **same** `@Name("org.jboss.seam.web.session")` as the built-in, with `@Install(precedence = Install.APPLICATION + 1)` (21) so the lib JAR wins over the framework default (`APPLICATION` = 20). **`@Install(precedence = 1)` would not override** (21 beats 20; 1 does not).

**Registry vs session map:** `Component.forName("org.jboss.seam.web.session")` only means a component is **installed** (metadata). Check the map explicitly:

```java
ScopeType.SESSION.getContext().get("org.jboss.seam.web.session");
// same key as HttpSession.getAttribute("org.jboss.seam.web.session")
```

Probe `/probe/lib/enhanced` prints `MAP_VALUE_CLASS`, `HTTPSESSION_VALUE_CLASS`, `SESSION_CONTEXT_KEYS`, and `HTTPSESSION_KEYS` before calling `getInstance`.

Common reasons a lib JAR component does not load or is missing from the session map:

- No `seam.properties` in the lib JAR → archive never scanned
- No or stale `META-INF/jandex.idx` in the lib JAR → deploy failure or component missing from index
- Class not included in the Jandex index (plugin not run, wrong module)
- `@Install(false)`, wrong precedence, or failed `@Install` classDependencies on the component
- Component name mismatch in `Component.getInstance("…")` (use `@Name`, not class name)
- Checking the map before session exists or before `@Startup` / `getInstance` runs

## Quick run

From the repo root:

```bash
./scripts/run-wildfly36-session-it.sh --install-parent   # first time only
./scripts/run-wildfly36-session-it.sh
```

## Manual browser testing

```bash
./scripts/run-wildfly36-session-manual.sh
# → http://127.0.0.1:8180/seam-session-wf36/
```

Lib JAR probe: **http://127.0.0.1:8180/seam-session-wf36/probe/lib/enhanced**

## What is tested

- Servlet probes: `/probe/*`, `/core/*`, `/probe/lib/enhanced`
- `EnhancedSeamSession` from `WEB-INF/lib` (`LibJarNegativeWildFly36IT` covers missing lib marker)
- JSF pages + `SessionContextWildFly36IT` (26 tests) + `LibJarNegativeWildFly36IT` (1 test)

See `webapp/README.md` for Maven details.
