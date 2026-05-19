package org.jboss.seam.servlet;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.jboss.seam.contexts.PatchedServletLifecycle;
import org.jboss.seam.contexts.ServletLifecycle;
import org.jboss.seam.init.Initialization;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;

/**
 * @deprecated Use {@link org.jboss.seam.servlet.SeamListener} or
 * {@link org.jboss.seam.servlet.JakartaSeamListener}. Bootstrap no longer requires skipping
 * {@link org.jboss.seam.init.Initialization#init()} after ServletLifecycle guards post-init events.
 */
@Deprecated
public class PatchedSeamListener implements ServletContextListener {

    private static final LogProvider log = Logging.getLogProvider(PatchedSeamListener.class);

    @Override
    public void contextInitialized(ServletContextEvent event) {
        log.info("Welcome to Seam " + getClass().getPackage().getImplementationVersion());
        
        ServletLifecycle.beginApplication(event.getServletContext());
        try {
            // Do the initialization but skip the problematic endInitialization call
            Initialization init = new Initialization(event.getServletContext()).create();
            
            // Manually call the parts of init() that we need, but skip ServletLifecycle.endInitialization()
            // This is equivalent to what Initialization.init() does, minus the Events call
            log.info("Completing Seam initialization with patched approach");
            PatchedServletLifecycle.endInitialization();
            
        } catch (Exception e) {
            log.error("could not start Seam with patched approach", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        log.info("Seam is shutting down...");
        ServletLifecycle.endApplication(event.getServletContext());
    }
}
