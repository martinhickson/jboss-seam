package org.jboss.seam.example.sessionwf36.lib;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Startup;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.web.Session;

/**
 * App override of Seam's built-in {@link Session} ({@code org.jboss.seam.web.session}).
 * Same component name; {@code @Install(precedence = Install.APPLICATION + 1)} (21) wins over
 * the framework class with default {@link Install#APPLICATION} (20).
 */
@Name("org.jboss.seam.web.session")
@Scope(ScopeType.SESSION)
@BypassInterceptors
@Startup
@Install(precedence = Install.APPLICATION + 1)
public class EnhancedSeamSession extends Session {

    private int libHits;

    public int incrementAndGet() {
        libHits++;
        return libHits;
    }

    public int getLibHits() {
        return libHits;
    }

    public String getSource() {
        return "WEB-INF/lib";
    }
}
