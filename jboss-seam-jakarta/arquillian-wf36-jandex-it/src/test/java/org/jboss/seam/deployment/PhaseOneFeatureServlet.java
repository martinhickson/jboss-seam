package org.jboss.seam.deployment;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jboss.seam.Component;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.contexts.ServletLifecycle;
import org.jboss.seam.core.Events;
import org.jboss.seam.jakarta.it.jandex.PhaseOneAction;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;

public class PhaseOneFeatureServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        boolean startedRequestContext = false;
        try {
            if (!Contexts.isEventContextActive()) {
                ServletLifecycle.beginRequest(req, req.getServletContext());
                ServletLifecycle.resumeConversation(req);
                startedRequestContext = true;
            }

            Name name = PhaseOneAction.class.getAnnotation(Name.class);
            boolean hasName = name != null && "phaseOneAction".equals(name.value());

            Field dependencyField = PhaseOneAction.class.getDeclaredField("phaseOneDependency");
            In in = dependencyField.getAnnotation(In.class);
            boolean hasInBijection = in != null && in.create();

            Method observerMethod = PhaseOneAction.class.getDeclaredMethod("onPhaseOneEvent", String.class);
            Observer observer = observerMethod.getAnnotation(Observer.class);
            boolean hasObserver = observer != null && Arrays.asList(observer.value()).contains("phase1.event");

            boolean hasBijectionInterceptorClass = false;
            try {
                Class.forName("org.jboss.seam.core.BijectionInterceptor", false, Thread.currentThread().getContextClassLoader());
                hasBijectionInterceptorClass = true;
            } catch (ClassNotFoundException ignored) {
                hasBijectionInterceptorClass = false;
            }

            boolean contextApiCallable;
            boolean contextEvent;
            boolean contextSession;
            boolean contextConversation;
            try {
                contextEvent = Contexts.isEventContextActive();
                contextSession = Contexts.isSessionContextActive();
                contextConversation = Contexts.isConversationContextActive();
                contextApiCallable = true;
            } catch (RuntimeException e) {
                contextEvent = false;
                contextSession = false;
                contextConversation = false;
                contextApiCallable = false;
            }

            String bijection = "MISSING";
            String event = "MISSING";
            try {
                PhaseOneAction action = (PhaseOneAction) Component.getInstance("phaseOneAction", true);
                if (action != null) {
                    bijection = action.readDependency();
                    Events.instance().raiseEvent("phase1.event", "event-ok");
                    event = action.getLastObserved();
                }
            } catch (RuntimeException e) {
                bijection = "MISSING";
                event = "MISSING";
            }

            boolean pass = hasName
                    && hasInBijection
                    && hasObserver
                    && hasBijectionInterceptorClass
                    && contextApiCallable
                    && contextEvent
                    && "dep-ok".equals(bijection)
                    && "event-ok".equals(event);

            resp.setContentType("text/plain");
            resp.getWriter().write("HAS_NAME=" + hasName + "\n");
            resp.getWriter().write("HAS_IN_BIJECTION=" + hasInBijection + "\n");
            resp.getWriter().write("HAS_OBSERVER=" + hasObserver + "\n");
            resp.getWriter().write("HAS_BIJECTION_INTERCEPTOR_CLASS=" + hasBijectionInterceptorClass + "\n");
            resp.getWriter().write("CONTEXT_API_CALLABLE=" + contextApiCallable + "\n");
            resp.getWriter().write("CONTEXT_EVENT=" + contextEvent + "\n");
            resp.getWriter().write("CONTEXT_SESSION=" + contextSession + "\n");
            resp.getWriter().write("CONTEXT_CONVERSATION=" + contextConversation + "\n");
            resp.getWriter().write("BIJECTION=" + bijection + "\n");
            resp.getWriter().write("EVENT=" + event + "\n");
            resp.getWriter().write("INTERCEPTOR=" + hasBijectionInterceptorClass + "\n");
            resp.getWriter().write("OVERALL=" + (pass ? "PASS" : "FAIL") + "\n");
        } catch (Exception e) {
            throw new ServletException("Failed phase1 seam feature probe", e);
        } finally {
            if (startedRequestContext) {
                ServletLifecycle.endRequest(req);
            }
        }
    }
}
