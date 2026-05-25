package org.jboss.seam.example.booking.test;

import java.io.PrintWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.jboss.seam.Component;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.web.Session;

/**
 * Reports HttpSession attribute vs Seam session context map lookup for
 * {@code org.jboss.seam.web.session} (production failure mode: map null, attribute set).
 */
public final class BookingSessionComponentProbe {

    public static final String SESSION_COMPONENT_NAME = "org.jboss.seam.web.session";

    private BookingSessionComponentProbe() {
    }

    public static void write(PrintWriter out, HttpServletRequest req) {
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
