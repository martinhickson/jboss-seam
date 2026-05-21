package org.jboss.seam.jakarta.it.jandex;

import java.io.IOException;
import java.io.PrintWriter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;
import org.jboss.seam.servlet.ContextualHttpServletRequest;

/**
 * Performs Seam {@link Identity#login()} inside a full request context.
 * Optional {@code rotateSessionId=true} calls {@link HttpServletRequest#changeSessionId()}.
 */
public class LoginProbeServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        handle(req, resp);
    }

    @Override
    protected void doPost(final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        handle(req, resp);
    }

    private void handle(final HttpServletRequest req, final HttpServletResponse resp)
            throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                String username = param(req, "username", "testuser");
                String password = param(req, "password", "secret");
                boolean rotate = "true".equalsIgnoreCase(param(req, "rotateSessionId", "false"));

                HttpSession before = req.getSession(false);
                String idBefore = before == null ? "" : before.getId();

                Credentials credentials = Identity.instance().getCredentials();
                credentials.setUsername(username);
                credentials.setPassword(password);

                String loginResult = Identity.instance().login();
                boolean loggedIn = Identity.instance().isLoggedIn();

                String idAfterLogin = req.getSession(false) == null ? "" : req.getSession(false).getId();
                boolean rotated = false;
                String idAfterRotate = idAfterLogin;

                if (rotate && loggedIn) {
                    String newId = req.changeSessionId();
                    rotated = true;
                    idAfterRotate = newId;
                }

                resp.setContentType("text/plain; charset=UTF-8");
                PrintWriter out = resp.getWriter();
                out.println("LOGIN_RESULT=" + (loginResult == null ? "" : loginResult));
                out.println("IDENTITY_LOGGED_IN=" + loggedIn);
                out.println("SESSION_ID_BEFORE=" + idBefore);
                out.println("SESSION_ID_AFTER_LOGIN=" + idAfterLogin);
                out.println("ROTATED_SESSION_ID=" + rotated);
                out.println("SESSION_ID_AFTER_ROTATE=" + idAfterRotate);
                out.println("REQUESTED_SESSION_ID=" + req.getRequestedSessionId());
                SessionComponentProbe.write(out, req);
            }
        }.run();
    }

    private static String param(HttpServletRequest req, String name, String defaultValue) {
        String value = req.getParameter(name);
        return value == null || value.isEmpty() ? defaultValue : value;
    }
}
