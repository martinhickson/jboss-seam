package org.jboss.seam.jakarta.it.jandex;

import java.io.PrintWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.jboss.seam.Component;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.web.Session;

/**
 * Shared reporting for HttpSession attribute vs Seam session context map lookup
 * ({@code Contexts.getSessionContext().get("org.jboss.seam.web.session")}).
 */
public final class SessionComponentProbe {

    static final String SESSION_COMPONENT_NAME = "org.jboss.seam.web.session";

    private SessionComponentProbe() {
    }

    static void write(PrintWriter out, HttpServletRequest req) {
        HttpSession httpSession = req.getSession(false);
        Object httpAttribute = httpSession == null
                ? null
                : httpSession.getAttribute(SESSION_COMPONENT_NAME);
        boolean sessionContextActive = Contexts.isSessionContextActive();
        Object mapValue = sessionContextActive
                ? Contexts.getSessionContext().get(SESSION_COMPONENT_NAME)
                : null;
        Component registry = Component.forName(SESSION_COMPONENT_NAME);
        Session seamSession = sessionContextActive ? Session.getInstance() : null;

        out.println("SESSION_CONTEXT_ACTIVE=" + sessionContextActive);
        out.println("HAS_SEAM_SESSION_KEY=" + (httpAttribute != null));
        out.println("HAS_MAP_KEY=" + (mapValue != null));
        out.println("MAP_EQUALS_HTTPSESSION=" + (httpAttribute != null && httpAttribute == mapValue));
        out.println("HTTPSESSION_VALUE_CLASS="
                + (httpAttribute == null ? "" : httpAttribute.getClass().getName()));
        out.println("MAP_VALUE_CLASS="
                + (mapValue == null ? "" : mapValue.getClass().getName()));
        out.println("REGISTRY_BEAN_CLASS="
                + (registry == null ? "" : registry.getBeanClass().getName()));
        out.println("SESSION_GETINSTANCE_PRESENT=" + (seamSession != null));
        out.println("SESSION_IS_INVALID=" + (seamSession != null && seamSession.isInvalid()));
    }
}
