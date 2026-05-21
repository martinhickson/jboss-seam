package org.jboss.seam.example.sessionwf36;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jboss.seam.Component;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.core.Events;
import org.jboss.seam.core.Manager;
import org.jboss.seam.security.AuthorizationException;
import org.jboss.seam.security.Identity;
import org.jboss.seam.security.NotLoggedInException;
import org.jboss.seam.servlet.ContextualHttpServletRequest;

/**
 * HTTP probes for conversation, {@link Events}, and application scope on WildFly 36.
 */
public class CoreSeamProbeServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String path = req.getPathInfo();
        if (path == null) {
            path = "/";
        }

        if (path.startsWith("/conversation")) {
            handleConversation(req, resp, conversationAction(path));
            return;
        }
        if ("/application".equals(path)) {
            handleApplication(req, resp);
            return;
        }
        if ("/bijection".equals(path)) {
            handleBijection(req, resp);
            return;
        }
        if ("/outjection".equals(path)) {
            handleOutjection(req, resp);
            return;
        }
        if ("/scopes".equals(path)) {
            handleScopes(req, resp);
            return;
        }
        if (path.startsWith("/identity")) {
            handleIdentity(req, resp, path);
            return;
        }
        if (path.startsWith("/restrict")) {
            handleRestrict(req, resp, path);
            return;
        }

        resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown core probe: " + path);
    }

    private void handleConversation(
            HttpServletRequest req,
            HttpServletResponse resp,
            String action) throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                String signal = signal(req);
                Manager manager = Manager.instance();

                if ("start".equals(action)) {
                    manager.beginConversation();
                }

                ConversationCounter counter =
                        (ConversationCounter) Component.getInstance("conversationCounter", true);
                counter.markStep();
                Events.instance().raiseEvent("probe.conversation.signal", signal);

                boolean ended = false;
                if ("end".equals(action)) {
                    manager.endConversation(false);
                    ended = true;
                }

                boolean pass = manager.getCurrentConversationId() != null
                        && counter.getSteps() > 0
                        && "dep-ok".equals(counter.getDependencyValue())
                        && signal.equals(counter.getLastSignal());

                resp.setContentType("text/plain;charset=UTF-8");
                resp.getWriter().println("ACTION=" + action);
                resp.getWriter().println("CID=" + manager.getCurrentConversationId());
                resp.getWriter().println("CID_PARAMETER=" + manager.getConversationIdParameter());
                resp.getWriter().println("LONG_RUNNING=" + manager.isLongRunningConversation());
                resp.getWriter().println("STEPS=" + counter.getSteps());
                resp.getWriter().println("LAST_SIGNAL=" + counter.getLastSignal());
                resp.getWriter().println("DEPENDENCY=" + counter.getDependencyValue());
                resp.getWriter().println("ENDED=" + ended);
                resp.getWriter().println("OVERALL=" + (pass ? "PASS" : "FAIL"));
            }
        }.run();
    }

    private void handleBijection(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                BijectionAction action = (BijectionAction) Component.getInstance("bijectionAction", true);
                Events.instance().raiseEvent("probe.bijection.event", "event-ok");

                boolean pass = Contexts.isEventContextActive()
                        && Contexts.isSessionContextActive()
                        && "dep-ok".equals(action.readDependency())
                        && "event-ok".equals(action.getLastObserved());

                resp.setContentType("text/plain;charset=UTF-8");
                resp.getWriter().println("CONTEXT_EVENT=" + Contexts.isEventContextActive());
                resp.getWriter().println("CONTEXT_SESSION=" + Contexts.isSessionContextActive());
                resp.getWriter().println("BIJECTION=" + action.readDependency());
                resp.getWriter().println("EVENT=" + action.getLastObserved());
                resp.getWriter().println("OVERALL=" + (pass ? "PASS" : "FAIL"));
            }
        }.run();
    }

    private void handleOutjection(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                String signal = signal(req);
                String eventSignal = signal + "-event";

                OutjectionAction action = (OutjectionAction) Component.getInstance("outjectionAction", true);
                String result = action.execute(signal);
                Events.instance().raiseEvent("probe.outjection.signal", eventSignal);
                Object outjected = Contexts.getEventContext().get("probeOut");

                boolean pass = ("dep-ok:" + signal).equals(result)
                        && ("out-" + signal).equals(outjected)
                        && eventSignal.equals(action.getObservedSignal());

                resp.setContentType("text/plain;charset=UTF-8");
                resp.getWriter().println("SIGNAL=" + signal);
                resp.getWriter().println("RESULT=" + result);
                resp.getWriter().println("OUTJECTION=" + outjected);
                resp.getWriter().println("OBSERVED=" + action.getObservedSignal());
                resp.getWriter().println("OVERALL=" + (pass ? "PASS" : "FAIL"));
            }
        }.run();
    }

    private void handleScopes(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                String signal = signal(req);

                SessionEventsState sessionState =
                        (SessionEventsState) Component.getInstance("sessionEventsState", true);
                ApplicationCounter applicationState =
                        (ApplicationCounter) Component.getInstance("applicationCounter", true);

                int sessionHits = sessionState.incrementAndGet();
                int applicationHits = applicationState.incrementAndGet();
                Events.instance().raiseEvent("probe.scopes.signal", signal);

                boolean pass = sessionHits > 0
                        && applicationHits > 0
                        && "dep-ok".equals(sessionState.getDependencyValue())
                        && signal.equals(sessionState.getLastSignal());

                resp.setContentType("text/plain;charset=UTF-8");
                resp.getWriter().println("SIGNAL=" + signal);
                resp.getWriter().println("SESSION_HITS=" + sessionHits);
                resp.getWriter().println("APPLICATION_HITS=" + applicationHits);
                resp.getWriter().println("DEPENDENCY=" + sessionState.getDependencyValue());
                resp.getWriter().println("LAST_SIGNAL=" + sessionState.getLastSignal());
                resp.getWriter().println("OVERALL=" + (pass ? "PASS" : "FAIL"));
            }
        }.run();
    }

    private void handleIdentity(HttpServletRequest req, HttpServletResponse resp, String path)
            throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                Identity identity = Identity.instance();

                if ("/identity/login".equals(path)) {
                    String username = req.getParameter("username");
                    String password = req.getParameter("password");
                    identity.getCredentials().setUsername(username);
                    identity.getCredentials().setPassword(password);
                    String loginResult = identity.login();
                    writeIdentityProbe(resp, identity, loginResult != null ? loginResult : "failed");
                    return;
                }

                if ("/identity/logout".equals(path)) {
                    identity.logout();
                    writeIdentityProbe(resp, identity, "loggedOut");
                    return;
                }

                if ("/identity/status".equals(path) || "/identity".equals(path)) {
                    writeIdentityProbe(resp, identity, "status");
                    return;
                }

                resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown identity probe: " + path);
            }
        }.run();
    }

    private static void writeIdentityProbe(
            HttpServletResponse resp,
            Identity identity,
            String loginResult) throws IOException {
        boolean loggedIn = identity.isLoggedIn();
        String username = identity.getPrincipal() == null ? "" : identity.getPrincipal().getName();

        boolean pass;
        if ("loggedIn".equals(loginResult)) {
            pass = loggedIn && identity.hasRole("user") && identity.hasRole("admin");
        } else if ("failed".equals(loginResult)) {
            pass = !loggedIn;
        } else if ("loggedOut".equals(loginResult)) {
            pass = !loggedIn;
        } else {
            pass = true;
        }

        resp.setContentType("text/plain;charset=UTF-8");
        resp.getWriter().println("LOGGED_IN=" + loggedIn);
        resp.getWriter().println("USERNAME=" + username);
        resp.getWriter().println("HAS_ROLE_USER=" + identity.hasRole("user"));
        resp.getWriter().println("HAS_ROLE_ADMIN=" + identity.hasRole("admin"));
        if (loginResult != null) {
            resp.getWriter().println("LOGIN_RESULT=" + loginResult);
        }
        resp.getWriter().println("OVERALL=" + (pass ? "PASS" : "FAIL"));
    }

    private void handleRestrict(HttpServletRequest req, HttpServletResponse resp, String path)
            throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                ProtectedAction action = (ProtectedAction) Component.getInstance("protectedAction", true);
                String outcome = "UNKNOWN";
                String result = null;

                try {
                    if ("/restrict/greeting".equals(path)) {
                        result = action.getGreeting();
                        outcome = "OK";
                    } else if ("/restrict/admin".equals(path)) {
                        result = action.getAdminOnly();
                        outcome = "OK";
                    } else {
                        resp.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown restrict probe: " + path);
                        return;
                    }
                } catch (NotLoggedInException e) {
                    outcome = "NOT_LOGGED_IN";
                } catch (AuthorizationException e) {
                    outcome = "NOT_AUTHORIZED";
                }

                resp.setContentType("text/plain;charset=UTF-8");
                resp.getWriter().println("OUTCOME=" + outcome);
                resp.getWriter().println("RESULT=" + (result == null ? "null" : result));
                resp.getWriter().println("OVERALL=PASS");
            }
        }.run();
    }

    private void handleApplication(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                ApplicationCounter counter =
                        (ApplicationCounter) Component.getInstance("applicationCounter", true);
                int hits = counter.incrementAndGet();

                resp.setContentType("text/plain;charset=UTF-8");
                resp.getWriter().println("APPLICATION_HITS=" + hits);
                resp.getWriter().println("OVERALL=" + (hits > 0 ? "PASS" : "FAIL"));
            }
        }.run();
    }

    private static String conversationAction(String path) {
        if ("/conversation".equals(path) || "/conversation/".equals(path) || "/conversation/start".equals(path)) {
            return "start";
        }
        if ("/conversation/step".equals(path)) {
            return "step";
        }
        if ("/conversation/end".equals(path)) {
            return "end";
        }
        return "step";
    }

    private static String signal(HttpServletRequest req) {
        String signal = req.getParameter("signal");
        return signal == null || signal.trim().isEmpty() ? "default" : signal.trim();
    }
}
