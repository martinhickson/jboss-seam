package org.jboss.seam.jsf;

import java.util.Iterator;

import jakarta.faces.FacesException;
import jakarta.faces.context.ExceptionHandler;
import jakarta.faces.context.ExceptionHandlerWrapper;
import jakarta.faces.context.FacesContext;
import jakarta.faces.event.ExceptionQueuedEvent;
import jakarta.faces.event.ExceptionQueuedEventContext;

import org.jboss.seam.contexts.FacesLifecycle;
import org.jboss.seam.core.Manager;
import org.jboss.seam.exception.Exceptions;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;

/**
 * Routes unhandled JSF exceptions to Seam's {@link Exceptions} handler chain.
 */
public class SeamExceptionHandler extends ExceptionHandlerWrapper {

    private static final LogProvider log = Logging.getLogProvider(SeamExceptionHandler.class);

    private final ExceptionHandler wrapped;

    public SeamExceptionHandler(ExceptionHandler wrapped) {
        this.wrapped = wrapped;
    }

    @Override
    public ExceptionHandler getWrapped() {
        return wrapped;
    }

    @Override
    public void handle() throws FacesException {
        FacesContext facesContext = FacesContext.getCurrentInstance();
        Iterator<ExceptionQueuedEvent> events = getUnhandledExceptionQueuedEvents().iterator();

        while (events.hasNext()) {
            ExceptionQueuedEvent event = events.next();
            ExceptionQueuedEventContext context = event.getContext();
            Throwable throwable = context.getException();
            if (!(throwable instanceof Exception)) {
                continue;
            }

            Exception exception = (Exception) throwable;
            try {
                Exceptions.instance().handle(exception);
                if (isResponseComplete(facesContext)) {
                    endRequest(facesContext);
                    events.remove();
                }
            } catch (Exception unhandled) {
                if (isResponseComplete(facesContext)) {
                    endRequest(facesContext);
                    events.remove();
                } else {
                    log.debug("Seam did not handle exception; delegating to JSF", exception);
                }
            }
        }

        if (wrapped != null && !isResponseComplete(facesContext)) {
            wrapped.handle();
        }
    }

    private static boolean isResponseComplete(FacesContext facesContext) {
        return facesContext != null && facesContext.getResponseComplete();
    }

    private static void endRequest(FacesContext facesContext) {
        Manager.instance().endRequest(facesContext.getExternalContext().getSessionMap());
        FacesLifecycle.endRequest(facesContext.getExternalContext());
    }
}
