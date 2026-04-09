package org.jboss.seam.deployment;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.seam.Component;
import org.jboss.seam.core.Events;
import org.jboss.seam.jakarta.it.jandex.PhaseThreeApplicationState;
import org.jboss.seam.jakarta.it.jandex.PhaseThreeSessionState;
import org.jboss.seam.servlet.ContextualHttpServletRequest;

public class PhaseThreeFeatureServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                String signal = signal(req);

                PhaseThreeSessionState sessionState =
                        (PhaseThreeSessionState) Component.getInstance("phaseThreeSessionState", true);
                PhaseThreeApplicationState applicationState =
                        (PhaseThreeApplicationState) Component.getInstance("phaseThreeApplicationState", true);

                int sessionHits = sessionState.incrementAndGet();
                int totalHits = applicationState.incrementAndGet();
                Events.instance().raiseEvent("phase3.signal", signal);

                boolean pass = sessionHits > 0
                        && totalHits > 0
                        && "dep-ok".equals(sessionState.getDependencyValue())
                        && signal.equals(sessionState.getLastSignal());

                resp.setContentType("text/plain");
                resp.getWriter().write("SIGNAL=" + signal + "\n");
                resp.getWriter().write("SESSION_HITS=" + sessionHits + "\n");
                resp.getWriter().write("APPLICATION_HITS=" + totalHits + "\n");
                resp.getWriter().write("DEPENDENCY=" + sessionState.getDependencyValue() + "\n");
                resp.getWriter().write("LAST_SIGNAL=" + sessionState.getLastSignal() + "\n");
                resp.getWriter().write("OVERALL=" + (pass ? "PASS" : "FAIL") + "\n");
            }
        }.run();
    }

    private static String signal(HttpServletRequest req) {
        String signal = req.getParameter("signal");
        return signal == null || signal.trim().isEmpty() ? "phase3-default" : signal.trim();
    }
}
