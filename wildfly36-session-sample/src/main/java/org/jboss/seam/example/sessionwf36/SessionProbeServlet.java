package org.jboss.seam.example.sessionwf36;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.jboss.seam.Component;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.contexts.ServletLifecycle;
import org.jboss.seam.servlet.ContextualHttpServletRequest;

/**
 * HTTP probe for Seam session context binding and HttpSession-backed state.
 *
 * <ul>
 *   <li>{@code /probe/raw} — no Seam request lifecycle (context should be inactive)</li>
 *   <li>{@code /probe/manual} — {@link ServletLifecycle#beginRequest} only</li>
 *   <li>{@code /probe/servlet} — full {@link ContextualHttpServletRequest}</li>
 * </ul>
 */
public class SessionProbeServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = req.getPathInfo();
        if (path == null) {
            path = "/";
        }

        switch (path) {
            case "/raw":
                writeProbe(resp, false, false, 0, null, null);
                break;
            case "/manual":
                boolean started = false;
                try {
                    if (!Contexts.isEventContextActive()) {
                        ServletLifecycle.beginRequest(req, req.getServletContext());
                        ServletLifecycle.resumeConversation(req);
                        started = true;
                    }
                    writeActiveProbe(req, resp);
                } finally {
                    if (started) {
                        ServletLifecycle.endRequest(req);
                    }
                }
                break;
            case "/servlet":
                new ContextualHttpServletRequest(req) {
                    @Override
                    public void process() throws Exception {
                        writeActiveProbe(req, resp);
                    }
                }.run();
                break;
            default:
                resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown probe: " + path);
        }
    }

    private void writeActiveProbe(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        boolean sessionContextActive = Contexts.isSessionContextActive();
        boolean eventContextActive = Contexts.isEventContextActive();

        int componentHits = 0;
        String componentError = null;
        if (sessionContextActive) {
            try {
                SessionCounter counter = (SessionCounter) Component.getInstance("sessionCounter", true);
                if (counter != null) {
                    componentHits = counter.incrementAndGet();
                } else {
                    componentError = "sessionCounter component null";
                }
            } catch (RuntimeException e) {
                componentError = e.getClass().getSimpleName() + ": " + e.getMessage();
            }

            String marker = req.getParameter("marker");
            if (marker != null && !marker.isEmpty()) {
                Contexts.getSessionContext().set("probeMarker", marker);
            }
        }

        String contextMarker = null;
        if (sessionContextActive && Contexts.getSessionContext() != null) {
            Object value = Contexts.getSessionContext().get("probeMarker");
            contextMarker = value == null ? null : String.valueOf(value);
        }

        HttpSession httpSession = req.getSession(false);
        String httpSessionId = httpSession == null ? null : httpSession.getId();

        writeProbe(resp, eventContextActive, sessionContextActive, componentHits, contextMarker, httpSessionId);
        if (componentError != null) {
            resp.getWriter().println("COMPONENT_ERROR=" + componentError);
        }
    }

    private static void writeProbe(
            HttpServletResponse resp,
            boolean eventContext,
            boolean sessionContext,
            int componentHits,
            String contextMarker,
            String httpSessionId) throws IOException {
        resp.setContentType("text/plain;charset=UTF-8");
        PrintWriter out = resp.getWriter();
        out.println("EVENT_CONTEXT=" + eventContext);
        out.println("SESSION_CONTEXT=" + sessionContext);
        out.println("COMPONENT_HITS=" + componentHits);
        out.println("CONTEXT_MARKER=" + (contextMarker == null ? "null" : contextMarker));
        out.println("HTTP_SESSION_ID=" + (httpSessionId == null ? "null" : httpSessionId));
    }
}
