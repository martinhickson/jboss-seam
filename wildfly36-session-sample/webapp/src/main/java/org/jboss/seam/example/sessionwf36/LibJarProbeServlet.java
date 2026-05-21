package org.jboss.seam.example.sessionwf36;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.contexts.Context;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.example.sessionwf36.lib.EnhancedSeamSession;
import org.jboss.seam.servlet.ContextualHttpServletRequest;
import org.jboss.seam.web.Session;

/**
 * Probes {@link EnhancedSeamSession} from a {@code WEB-INF/lib} JAR by reading the
 * Seam session context map and {@link HttpSession} attributes directly (not only
 * {@link Component#getInstance(String, boolean)}).
 *
 * <ul>
 *   <li>{@code /probe/lib/enhanced} — map + registry + optional getInstance</li>
 * </ul>
 */
public class LibJarProbeServlet extends HttpServlet {

    private static final String COMPONENT_NAME = "org.jboss.seam.web.session";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = req.getPathInfo();
        if (path == null) {
            path = "/";
        }

        if ("/enhanced".equals(path)) {
            new ContextualHttpServletRequest(req) {
                @Override
                public void process() throws Exception {
                    writeEnhancedProbe(req, resp);
                }
            }.run();
            return;
        }

        resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown lib probe: " + path);
    }

    private void writeEnhancedProbe(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/plain;charset=UTF-8");
        PrintWriter out = resp.getWriter();

        boolean sessionContext = Contexts.isSessionContextActive();
        Component registryComponent = sessionContext && Contexts.isApplicationContextActive()
                ? Component.forName(COMPONENT_NAME) : null;
        boolean inRegistry = registryComponent != null;

        String registryBeanClass = registryComponent == null
                ? "null"
                : registryComponent.getBeanClass().getName();

        // --- read session map BEFORE Component.getInstance (the production bug path) ---
        String mapValueClass = "null";
        boolean mapIsSet = false;
        List<String> sessionContextKeys = Collections.emptyList();
        if (sessionContext) {
            Context sessionCtx = ScopeType.SESSION.getContext();
            mapIsSet = sessionCtx.isSet(COMPONENT_NAME);
            Object mapValue = sessionCtx.get(COMPONENT_NAME);
            mapValueClass = mapValue == null ? "null" : mapValue.getClass().getName();
            sessionContextKeys = sortedNames(sessionCtx.getNames());
        }

        // --- read HttpSession attribute map directly ---
        String httpSessionValueClass = "null";
        boolean httpSessionHasKey = false;
        List<String> httpSessionKeys = Collections.emptyList();
        HttpSession httpSession = req.getSession(false);
        if (httpSession != null) {
            httpSessionKeys = sortedHttpSessionNames(httpSession);
            httpSessionHasKey = httpSession.getAttribute(COMPONENT_NAME) != null;
            Object httpAttr = httpSession.getAttribute(COMPONENT_NAME);
            httpSessionValueClass = httpAttr == null ? "null" : httpAttr.getClass().getName();
        }

        String installed = "false";
        String getInstanceClass = "null";
        String source = "null";
        int libHits = 0;
        String error = null;

        if (sessionContext) {
            try {
                Object instance = Component.getInstance(COMPONENT_NAME, false);
                if (instance == null) {
                    instance = Component.getInstance(COMPONENT_NAME, true);
                }
                if (instance != null) {
                    installed = "true";
                    getInstanceClass = instance.getClass().getName();
                    if (instance instanceof EnhancedSeamSession) {
                        libHits = ((EnhancedSeamSession) instance).incrementAndGet();
                        source = ((EnhancedSeamSession) instance).getSource();
                    } else if (instance instanceof Session) {
                        error = "getInstance returned built-in Session, expected EnhancedSeamSession";
                    }
                } else {
                    error = COMPONENT_NAME + " getInstance returned null";
                }
            } catch (RuntimeException e) {
                error = e.getClass().getSimpleName() + ": " + e.getMessage();
            }
        } else {
            error = "session context inactive";
        }

        boolean mapMatchesHttpSession = !"null".equals(mapValueClass)
                && mapValueClass.equals(httpSessionValueClass);
        boolean mapMatchesGetInstance = !"null".equals(mapValueClass)
                && mapValueClass.equals(getInstanceClass);

        boolean pass = sessionContext && inRegistry
                && mapIsSet
                && mapValueClass.contains("EnhancedSeamSession")
                && httpSessionValueClass.contains("EnhancedSeamSession")
                && registryBeanClass.contains("EnhancedSeamSession")
                && "WEB-INF/lib".equals(source)
                && error == null;

        out.println("OVERALL=" + (pass ? "PASS" : "FAIL"));
        out.println("SESSION_CONTEXT=" + sessionContext);
        out.println("IN_REGISTRY=" + inRegistry);
        out.println("REGISTRY_BEAN_CLASS=" + registryBeanClass);
        out.println("MAP_IS_SET=" + mapIsSet);
        out.println("MAP_VALUE_CLASS=" + mapValueClass);
        out.println("HTTPSESSION_HAS_KEY=" + httpSessionHasKey);
        out.println("HTTPSESSION_VALUE_CLASS=" + httpSessionValueClass);
        out.println("MAP_MATCHES_HTTPSESSION=" + mapMatchesHttpSession);
        out.println("GETINSTANCE_CLASS=" + getInstanceClass);
        out.println("MAP_MATCHES_GETINSTANCE=" + mapMatchesGetInstance);
        out.println("SESSION_CONTEXT_KEY_COUNT=" + sessionContextKeys.size());
        out.println("SESSION_CONTEXT_KEYS=" + String.join(",", sessionContextKeys));
        out.println("HTTPSESSION_KEY_COUNT=" + httpSessionKeys.size());
        out.println("HTTPSESSION_KEYS=" + String.join(",", httpSessionKeys));
        out.println("INSTALLED=" + installed);
        out.println("LIB_HITS=" + libHits);
        out.println("SOURCE=" + source);
        if (error != null) {
            out.println("ERROR=" + error);
        }
    }

    private static List<String> sortedNames(String[] names) {
        List<String> keys = new ArrayList<String>();
        if (names != null) {
            for (String name : names) {
                keys.add(name);
            }
        }
        Collections.sort(keys);
        return keys;
    }

    private static List<String> sortedHttpSessionNames(HttpSession session) {
        List<String> keys = new ArrayList<String>();
        Enumeration<String> names = session.getAttributeNames();
        while (names.hasMoreElements()) {
            keys.add(names.nextElement());
        }
        Collections.sort(keys);
        return keys;
    }
}
