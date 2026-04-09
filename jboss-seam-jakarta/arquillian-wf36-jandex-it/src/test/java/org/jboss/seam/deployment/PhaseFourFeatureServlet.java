package org.jboss.seam.deployment;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.seam.Component;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.core.Events;
import org.jboss.seam.jakarta.it.jandex.PhaseFourAction;
import org.jboss.seam.servlet.ContextualHttpServletRequest;

public class PhaseFourFeatureServlet extends HttpServlet {

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        new ContextualHttpServletRequest(req) {
            @Override
            public void process() throws Exception {
                String signal = signal(req);
                String eventSignal = signal + "-event";

                PhaseFourAction action = (PhaseFourAction) Component.getInstance("phaseFourAction", true);
                String result = action.execute(signal);
                Events.instance().raiseEvent("phase4.signal", eventSignal);
                Object outjected = Contexts.getEventContext().get("phaseFourOut");

                boolean outjectionOk = ("out-" + signal).equals(outjected);
                boolean observerOk = eventSignal.equals(action.getObservedSignal());
                boolean pass = ("dep-ok:" + signal).equals(result)
                        && outjectionOk
                        && observerOk;

                resp.setContentType("text/plain");
                resp.getWriter().write("SIGNAL=" + signal + "\n");
                resp.getWriter().write("RESULT=" + result + "\n");
                resp.getWriter().write("OUTJECTION=" + outjected + "\n");
                resp.getWriter().write("OBSERVED=" + action.getObservedSignal() + "\n");
                resp.getWriter().write("OVERALL=" + (pass ? "PASS" : "FAIL") + "\n");
            }
        }.run();
    }

    private static String signal(HttpServletRequest req) {
        String signal = req.getParameter("signal");
        return signal == null || signal.trim().isEmpty() ? "phase4-default" : signal.trim();
    }
}
