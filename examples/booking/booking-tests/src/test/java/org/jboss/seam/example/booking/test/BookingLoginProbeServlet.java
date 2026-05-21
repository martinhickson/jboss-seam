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
 * Performs Seam {@link Identity#login()} and reports session component state (booking credentials).
 */
public class BookingLoginProbeServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                String username = req.getParameter("username");
                String password = req.getParameter("password");
                if (username == null || username.isEmpty()) {
                    username = "gavin";
                }
                if (password == null || password.isEmpty()) {
                    password = "foobar";
                }

                Identity identity = Identity.instance();
                identity.setUsername(username);
                identity.setPassword(password);
                String loginResult = identity.login();

                resp.setContentType("text/plain; charset=UTF-8");
                PrintWriter out = resp.getWriter();
                out.println("LOGIN_RESULT=" + (loginResult == null ? "" : loginResult));
                out.println("IDENTITY_LOGGED_IN=" + identity.isLoggedIn());
                BookingSessionComponentProbe.write(out, req);
            }
        }.run();
    }
}
