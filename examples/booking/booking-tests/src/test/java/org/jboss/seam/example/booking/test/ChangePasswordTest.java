//$Id: ChangePasswordTest.java 5810 2007-07-16 06:46:47Z gavin $
package org.jboss.seam.example.booking.test;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.seam.Component;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.contexts.Lifecycle;
import org.jboss.seam.example.booking.User;
import org.jboss.seam.core.Manager;
import org.jboss.seam.security.Identity;
import org.jboss.shrinkwrap.api.Archive;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
public class ChangePasswordTest {

    @Deployment(name = "ChangePasswordTest")
    public static Archive<?> createDeployment() throws Exception {
        return Deployments.bookingDeployment()
                .addClass(ChangePasswordTest.class);
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
    public void testChangePassword() throws Exception {
        Identity identity = Identity.instance();

        Contexts.getSessionContext().set("user", new User("Gavin King", "foobar", "gavin"));
        identity.setUsername("gavin");
        identity.setPassword("foobar");
        identity.login();

        User user = sessionUser();
        assertEquals("Gavin King", user.getName());
        assertEquals("gavin", user.getUsername());
        assertEquals("foobar", user.getPassword());
        assertFalse(Manager.instance().isLongRunningConversation());
        assertTrue(identity.isLoggedIn());

        SimpleChangePassword changePassword = (SimpleChangePassword) Component.getInstance("changePassword");
        changePassword.changePassword("xxxyyy", "xxyyyx");

        user = sessionUser();
        assertEquals("Gavin King", user.getName());
        assertEquals("gavin", user.getUsername());
        assertEquals("foobar", user.getPassword());
        assertFalse(Manager.instance().isLongRunningConversation());
        assertTrue(identity.isLoggedIn());

        changePassword.changePassword("xxxyyy", "xxxyyy");

        user = sessionUser();
        assertEquals("Gavin King", user.getName());
        assertEquals("gavin", user.getUsername());
        assertEquals("xxxyyy", user.getPassword());
        assertFalse(Manager.instance().isLongRunningConversation());
        assertTrue(identity.isLoggedIn());

        user = sessionUser();
        assertEquals("xxxyyy", user.getPassword());
        changePassword.changePassword("foobar", "foobar");

        user = sessionUser();
        assertEquals("Gavin King", user.getName());
        assertEquals("gavin", user.getUsername());
        assertEquals("foobar", user.getPassword());
        assertFalse(Manager.instance().isLongRunningConversation());
        assertTrue(identity.isLoggedIn());
    }

    private static User sessionUser() {
        return (User) Contexts.getSessionContext().get("user");
    }
}
