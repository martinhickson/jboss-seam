package org.jboss.seam.deployment;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.seam.Component;
import org.jboss.seam.core.Events;
import org.jboss.seam.core.Manager;
import org.jboss.seam.jakarta.it.jandex.PhaseTwoConversationState;
import org.jboss.seam.servlet.ContextualHttpServletRequest;

public class PhaseTwoFeatureServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                String action = action(req);
                String signal = signal(req);

                Manager manager = Manager.instance();
                if ("start".equals(action)) {
                    manager.beginConversation();
                }

                PhaseTwoConversationState state =
                        (PhaseTwoConversationState) Component.getInstance("phaseTwoConversationState", true);
                state.markStep();
                Events.instance().raiseEvent("phase2.signal", signal);

                boolean ended = false;
                if ("end".equals(action)) {
                    manager.endConversation(false);
                    ended = true;
                }

                boolean pass = manager.getCurrentConversationId() != null
                        && state.getCounter() > 0
                        && !"MISSING".equals(state.getDependencyValue())
                        && signal.equals(state.getLastSignal());

                resp.setContentType("text/plain");
                resp.getWriter().write("ACTION=" + action + "\n");
                resp.getWriter().write("CID=" + manager.getCurrentConversationId() + "\n");
                resp.getWriter().write("CID_PARAMETER=" + manager.getConversationIdParameter() + "\n");
                resp.getWriter().write("LONG_RUNNING=" + manager.isLongRunningConversation() + "\n");
                resp.getWriter().write("COUNTER=" + state.getCounter() + "\n");
                resp.getWriter().write("LAST_SIGNAL=" + state.getLastSignal() + "\n");
                resp.getWriter().write("DEPENDENCY=" + state.getDependencyValue() + "\n");
                resp.getWriter().write("ENDED=" + ended + "\n");
                resp.getWriter().write("OVERALL=" + (pass ? "PASS" : "FAIL") + "\n");
            }
        }.run();
    }

    private static String action(HttpServletRequest req) {
        String path = req.getPathInfo();
        if (path == null || "/".equals(path) || "/start".equals(path)) {
            return "start";
        }
        if ("/step".equals(path)) {
            return "step";
        }
        if ("/end".equals(path)) {
            return "end";
        }
        return "step";
    }

    private static String signal(HttpServletRequest req) {
        String signal = req.getParameter("signal");
        return signal == null || signal.trim().isEmpty() ? "default" : signal.trim();
    }
}
