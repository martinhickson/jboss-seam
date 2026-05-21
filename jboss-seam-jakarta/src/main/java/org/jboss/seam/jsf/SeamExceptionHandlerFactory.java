package org.jboss.seam.jsf;

import jakarta.faces.context.ExceptionHandler;
import jakarta.faces.context.ExceptionHandlerFactory;

/**
 * Delegates to the container {@link ExceptionHandlerFactory} and wraps the
 * handler so Seam {@code pages.xml} / {@code exceptions.xml} rules run for
 * queued JSF exceptions (replacing the removed PreJsf2 handler on Jakarta Faces 4).
 */
public class SeamExceptionHandlerFactory extends ExceptionHandlerFactory {

    private final ExceptionHandlerFactory delegate;

    public SeamExceptionHandlerFactory() {
        this(null);
    }

    public SeamExceptionHandlerFactory(ExceptionHandlerFactory delegate) {
        super(delegate);
        this.delegate = delegate;
    }

    @Override
    public ExceptionHandlerFactory getWrapped() {
        return delegate;
    }

    @Override
    public ExceptionHandler getExceptionHandler() {
        ExceptionHandler parent = delegate != null ? delegate.getExceptionHandler() : null;
        return new SeamExceptionHandler(parent);
    }
}
