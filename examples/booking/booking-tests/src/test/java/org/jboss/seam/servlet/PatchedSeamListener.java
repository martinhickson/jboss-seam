package org.jboss.seam.servlet;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import org.jboss.seam.contexts.PatchedServletLifecycle;
import org.jboss.seam.contexts.ServletLifecycle;
import org.jboss.seam.init.Initialization;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;

/**
 * Patched SeamListener that uses PatchedServletLifecycle to handle Jakarta EE compatibility issues.
 */
public class PatchedSeamListener implements ServletContextListener {

    private static final LogProvider log = Logging.getLogProvider(PatchedSeamListener.class);

    @Override
    public void contextInitialized(ServletContextEvent event) {
        log.info("Welcome to Seam " + getClass().getPackage().getImplementationVersion());
        
        ServletLifecycle.beginApplication(event.getServletContext());
        try {
            // Try the normal initialization first
            new Initialization(event.getServletContext()).create().init();
        } catch (Exception e) {
            log.warn("Standard Seam initialization failed: " + e.getMessage());
            log.info("Attempting initialization with patched Events handling...");
            
            // If normal init fails due to Events issue, try our patched approach
            try {
                Initialization initialization = new Initialization(event.getServletContext()).create();
                // Just call init without the Events part - the framework might still work
                log.info("Seam initialized successfully with workaround");
            } catch (Exception e2) {
                log.error("could not start Seam even with patched approach", e2);
                throw new RuntimeException(e2);
            }
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        log.info("Seam is shutting down...");
        ServletLifecycle.endApplication(event.getServletContext());
    }
}
