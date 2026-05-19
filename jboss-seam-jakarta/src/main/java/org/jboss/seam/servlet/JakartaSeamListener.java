package org.jboss.seam.servlet;

import jakarta.servlet.http.HttpSessionEvent;

/**
 * Supported servlet bootstrap listener for Jakarta EE / WildFly deployments.
 *
 * <p>Delegates to the standard {@link SeamListener} lifecycle. Prefer this class name
 * in {@code web.xml} for Jakarta migrations to make the intent explicit; behaviour is
 * identical to {@link SeamListener} once {@link org.jboss.seam.contexts.ServletLifecycle}
 * guards bootstrap events when the {@code Events} component is not yet installed.</p>
 */
public class JakartaSeamListener extends SeamListener {

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        super.sessionCreated(event);
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        super.sessionDestroyed(event);
    }
}
