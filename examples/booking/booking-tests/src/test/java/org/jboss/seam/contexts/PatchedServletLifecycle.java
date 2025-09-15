package org.jboss.seam.contexts;

import org.jboss.seam.ScopeType;
import org.jboss.seam.core.Events;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;

/**
 * Patched version of ServletLifecycle that handles the Jakarta EE compatibility issue
 * where Events.instance() returns null during initialization.
 */
public class PatchedServletLifecycle extends ServletLifecycle {
    
    private static final LogProvider log = Logging.getLogProvider(PatchedServletLifecycle.class);
    
    public static void endInitialization() {
        Contexts.startup(ScopeType.APPLICATION);
        
        try {
            // Try to raise the postInitialization event, but handle the case where Events is not initialized
            Events events = Events.instance();
            if (events != null) {
                events.raiseEvent("org.jboss.seam.postInitialization");
            } else {
                log.warn("Events component not initialized during ServletLifecycle.endInitialization() - skipping postInitialization event");
            }
        } catch (Exception e) {
            log.warn("Failed to raise postInitialization event: " + e.getMessage() + " - continuing with initialization");
        }
        
        // Clean up contexts used during initialization
        Contexts.destroy(Contexts.getConversationContext());
        Contexts.conversationContext.set(null);
        Contexts.destroy(Contexts.getEventContext());
        Contexts.eventContext.set(null);
        Contexts.sessionContext.set(null);
        Contexts.applicationContext.set(null);
        
        log.debug("<<< End initialization (patched)");
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
