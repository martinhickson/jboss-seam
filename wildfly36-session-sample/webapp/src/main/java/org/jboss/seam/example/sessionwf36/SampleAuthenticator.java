package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.annotations.Name;
import org.jboss.seam.security.Identity;

/**
 * Minimal {@code authenticate-method} for Identity login probes (no database).
 */
@Name("authenticator")
public class SampleAuthenticator {

    public boolean authenticate() {
        Identity identity = Identity.instance();
        String username = identity.getCredentials().getUsername();
        String password = identity.getCredentials().getPassword();

        if ("demo".equals(username) && "secret".equals(password)) {
            identity.addRole("user");
            identity.addRole("admin");
            return true;
        }
        if ("guest".equals(username) && "guest".equals(password)) {
            identity.addRole("user");
            return true;
        }
        return false;
    }
}
