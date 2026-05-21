package org.jboss.seam.example.booking.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.CookieHandler;
import java.net.URL;
import java.util.Map;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * JSF + Seam conversation and cross-request session consistency tests (WildFly 36).
 */
@RunWith(Arquillian.class)
public class BookingJsfConversationWildFly36IT {

    private BookingHttpTestClient client;

    @Deployment(testable = false)
    public static WebArchive deployment() throws Exception {
        return BookingWildFly36Deployment.create();
    }

    @ArquillianResource
    private URL baseUrl;

    @Before
    public void installCookieManager() {
        client = new BookingHttpTestClient(baseUrl);
        client.installCookieManager();
    }

    @After
    public void clearCookieManager() {
        if (client != null) {
            client.clearCookieManager();
        }
        CookieHandler.setDefault(null);
    }

    @Test
    @RunAsClient
    public void templateAndPasswordPagesRenderWhenLoggedIn() throws Exception {
        client.getText(client.url("home.seam"));
        client.getProbeLogin("gavin", "foobar");
        String password = client.getText(client.url("password.seam"));
        assertTrue(password.contains("Change Password") || password.contains("password"));
        String conversations = client.getText(client.url("conversations.seam"));
        assertTrue(conversations.length() > 0);
    }

    @Test
    @RunAsClient
    public void sessionMapConsistentAcrossJsfAndServletProbes() throws Exception {
        client.getText(client.url("home.seam"));
        Map<String, String> afterHome = client.getProbe("jsf-home");
        BookingHttpTestClient.assertSessionComponentInMapAndHttpSession(afterHome);

        client.getProbeLogin("gavin", "foobar");
        client.getText(client.url("main.seam"));
        Map<String, String> afterMain = client.getProbe("jsf-main");
        BookingHttpTestClient.assertSessionComponentInMapAndHttpSession(afterMain);
        assertEquals("true", afterMain.get("USER_IN_SESSION"));

        Map<String, String> afterServletOnly = client.getProbe("servlet-only");
        BookingHttpTestClient.assertSessionComponentInMapAndHttpSession(afterServletOnly);
        assertEquals(afterMain.get("MAP_VALUE_CLASS"), afterServletOnly.get("MAP_VALUE_CLASS"));
    }
}
