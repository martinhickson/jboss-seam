package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.security.Restrict;
import org.jboss.seam.security.Identity;

@Name("protectedAction")
@Scope(ScopeType.EVENT)
public class ProtectedAction {

    @Restrict("#{identity.loggedIn}")
    public String getGreeting() {
        return "protected:" + Identity.instance().getPrincipal().getName();
    }

    @Restrict("#{identity.hasRole('admin')}")
    public String getAdminOnly() {
        return "admin-ok";
    }
}
