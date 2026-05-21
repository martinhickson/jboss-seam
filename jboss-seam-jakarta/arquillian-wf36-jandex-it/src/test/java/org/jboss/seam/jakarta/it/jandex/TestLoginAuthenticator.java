package org.jboss.seam.jakarta.it.jandex;

import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;

/**
 * Minimal authenticator for login/session ITs (user/secret).
 */
@Name("testLoginAuthenticator")
public class TestLoginAuthenticator {

    @In
    private Identity identity;

    @In
    private Credentials credentials;

    public boolean authenticate() {
        if ("testuser".equals(credentials.getUsername())
                && "secret".equals(credentials.getPassword())) {
            identity.addRole("user");
            return true;
        }
        return false;
    }
}
