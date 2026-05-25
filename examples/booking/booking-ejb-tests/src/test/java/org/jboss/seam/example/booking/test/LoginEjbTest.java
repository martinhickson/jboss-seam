package org.jboss.seam.example.booking.test;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OverProtocol;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.seam.Component;
import org.jboss.seam.contexts.Lifecycle;
import org.jboss.seam.core.Manager;
import org.jboss.seam.example.booking.User;
import org.jboss.seam.security.Identity;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(Arquillian.class)
public class LoginEjbTest {

    @Deployment(name = "LoginEjbTest")
    @OverProtocol("Servlet 5.0")
    public static Archive<?> createDeployment() throws Exception {
        return Deployments.bookingEarDeployment(LoginEjbTest.class);
    }

    @Before
    public void before() {
        Lifecycle.beginCall();
        Manager.instance().initializeTemporaryConversation();
    }

    @After
    public void after() {
        Lifecycle.endCall();
    }

    @Test
    public void testLoginViaStatelessAuthenticatorEjb() {
        Identity identity = Identity.instance();

        assertFalse(identity.isLoggedIn());
        identity.setUsername("gavin");
        identity.setPassword("foobar");
        identity.login();

        User user = (User) Component.getInstance("user");
        assertEquals("Gavin King", user.getName());
        assertEquals("gavin", user.getUsername());
        assertTrue(identity.isLoggedIn());

        identity.logout();
        assertFalse(identity.isLoggedIn());

        identity.setUsername("gavin");
        identity.setPassword("tiger");
        identity.login();
        assertFalse(identity.isLoggedIn());
    }
}
