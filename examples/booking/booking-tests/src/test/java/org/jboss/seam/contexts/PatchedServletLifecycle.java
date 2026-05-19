package org.jboss.seam.contexts;

import org.jboss.seam.ScopeType;
import org.jboss.seam.core.Events;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;

/**
 * @deprecated No longer required; {@link org.jboss.seam.contexts.ServletLifecycle#endInitialization()}
 * guards {@code org.jboss.seam.postInitialization} when the Events component is not yet installed.
 */
@Deprecated
public class PatchedServletLifecycle extends ServletLifecycle {
    
    private static final LogProvider log = Logging.getLogProvider(PatchedServletLifecycle.class);
    
    public static void endInitialization() {
        log.info("Starting patched Seam endInitialization...");
        
        try {
            Contexts.startup(ScopeType.APPLICATION);
            log.info("Application context startup successful");
        } catch (Exception e) {
            log.warn("Failed to start application context: " + e.getMessage() + " - continuing with initialization");
        }
        
        try {
            // Try to raise the postInitialization event, but handle the case where Events is not initialized
            Events events = Events.instance();
            if (events != null) {
                events.raiseEvent("org.jboss.seam.postInitialization");
                log.info("postInitialization event raised successfully");
            } else {
                log.warn("Events component not initialized during ServletLifecycle.endInitialization() - skipping postInitialization event");
            }
        } catch (Exception e) {
            log.warn("Failed to raise postInitialization event: " + e.getMessage() + " - continuing with initialization");
        }
        
        // Clean up contexts used during initialization
        try {
            if (Contexts.getConversationContext() != null) {
                Contexts.destroy(Contexts.getConversationContext());
            }
            Contexts.conversationContext.set(null);
            
            if (Contexts.getEventContext() != null) {
                Contexts.destroy(Contexts.getEventContext());
            }
            Contexts.eventContext.set(null);
            Contexts.sessionContext.set(null);
            Contexts.applicationContext.set(null);
            log.info("Context cleanup completed");
        } catch (Exception e) {
            log.warn("Exception during context cleanup: " + e.getMessage() + " - continuing");
        }
        
        log.info("Patched Seam initialization completed successfully");
    }
    
    public static void endReinitialization() {
        Contexts.startup(ScopeType.APPLICATION);
        
        try {
            // Try to raise the postReInitialization event, but handle the case where Events is not initialized
            Events events = Events.instance();
            if (events != null) {
                events.raiseEvent("org.jboss.seam.postReInitialization");
            } else {
                log.warn("Events component not initialized during ServletLifecycle.endReinitialization() - skipping postReInitialization event");
            }
        } catch (Exception e) {
            log.warn("Failed to raise postReInitialization event: " + e.getMessage() + " - continuing with reinitialization");
        }
        
        // Clean up contexts used during reinitialization
        Contexts.destroy(Contexts.getConversationContext());
        Contexts.conversationContext.set(null);
        Contexts.destroy(Contexts.getEventContext());
        Contexts.eventContext.set(null);
        Contexts.sessionContext.set(null);
        
        log.debug("<<< End re-initialization (patched)");
    }
}
