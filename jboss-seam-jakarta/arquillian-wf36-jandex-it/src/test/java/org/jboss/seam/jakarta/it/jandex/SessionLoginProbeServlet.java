package org.jboss.seam.jakarta.it.jandex;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.security.Identity;
import org.jboss.seam.servlet.ContextualHttpServletRequest;

/**
 * Reports HttpSession and Seam {@code org.jboss.seam.web.session} state for login ITs.
 */
public class SessionLoginProbeServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                String phase = req.getParameter("phase");
                if (phase == null || phase.isEmpty()) {
                    phase = "probe";
                }

                HttpSession httpSession = req.getSession(false);

                resp.setContentType("text/plain; charset=UTF-8");
                PrintWriter out = resp.getWriter();
                out.println("PHASE=" + phase);
                out.println("HTTP_SESSION_PRESENT=" + (httpSession != null));
                out.println("HTTP_SESSION_IS_NEW=" + (httpSession != null && httpSession.isNew()));
                out.println("HTTP_SESSION_ID=" + (httpSession == null ? "" : httpSession.getId()));
                out.println("REQUESTED_SESSION_ID=" + req.getRequestedSessionId());
                out.println("REQUESTED_SESSION_ID_VALID=" + req.isRequestedSessionIdValid());
                out.println("REQUESTED_EQUALS_SESSION_ID="
                        + (httpSession != null && httpSession.getId().equals(req.getRequestedSessionId())));
                SessionComponentProbe.write(out, req);
                out.println("IDENTITY_LOGGED_IN="
                        + (Contexts.isSessionContextActive() && Identity.instance().isLoggedIn()));
            }
        }.run();
    }
}
