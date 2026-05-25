package org.jboss.seam.example.booking.test;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.security.Identity;
import org.jboss.seam.servlet.ContextualHttpServletRequest;

/**
 * Servlet probe for Seam session component state after JSF or plain HTTP requests.
 */
public class BookingSeamSessionProbeServlet extends HttpServlet {

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

                resp.setContentType("text/plain; charset=UTF-8");
                PrintWriter out = resp.getWriter();
                out.println("PHASE=" + phase);
                BookingSessionComponentProbe.write(out, req);
                boolean identityLoggedIn = Contexts.isSessionContextActive() && Identity.instance().isLoggedIn();
                Object sessionUser = Contexts.isSessionContextActive()
                        ? Contexts.getSessionContext().get("user")
                        : null;
                out.println("IDENTITY_LOGGED_IN=" + identityLoggedIn);
                out.println("USER_IN_SESSION=" + (sessionUser != null));
            }
        }.run();
    }
}
