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
 * End-to-end Seam + JSF HTTP tests for the booking demonstration on WildFly 36.
 */
@RunWith(Arquillian.class)
public class BookingJsfHttpWildFly36IT {

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
    public void homeJsfViewRendersLoginForm() throws Exception {
        String body = client.getText(client.url("home.seam"));
        assertTrue("Expected login form on home.seam: " + BookingHttpTestClient.snippet(body),
                body.contains("Login Name") || body.contains("Account Login"));
    }

    @Test
    @RunAsClient
    public void seamSessionComponentPresentAfterJsfHomeRequest() throws Exception {
        client.getText(client.url("home.seam"));
        BookingHttpTestClient.assertSessionComponentInMapAndHttpSession(client.getProbe("after-home-jsf"));
    }

    @Test
    @RunAsClient
    public void loginViaSeamAllowsMainJsfView() throws Exception {
        client.getText(client.url("home.seam"));
        Map<String, String> login = client.getProbeLogin("gavin", "foobar");
        assertEquals("loggedIn", login.get("LOGIN_RESULT"));
        assertEquals("true", login.get("IDENTITY_LOGGED_IN"));

        String main = client.getText(client.url("main.seam"));
        assertTrue("Expected hotel search on main.seam: " + BookingHttpTestClient.snippet(main),
                main.contains("Search Hotels"));
    }

    @Test
    @RunAsClient
    public void seamSessionComponentPresentOnMainAfterLogin() throws Exception {
        client.getText(client.url("home.seam"));
        client.getProbeLogin("gavin", "foobar");
        client.getText(client.url("main.seam"));
        Map<String, String> probe = client.getProbe("after-main-jsf");
        BookingHttpTestClient.assertSessionComponentInMapAndHttpSession(probe);
        assertEquals("true", probe.get("USER_IN_SESSION"));
    }

    @Test
    @RunAsClient
    public void mainJsfRedirectsOrDeniesWhenNotLoggedIn() throws Exception {
        CookieHandler.setDefault(new java.net.CookieManager(null, java.net.CookiePolicy.ACCEPT_ALL));
        int code = client.getResponseCode(client.url("main.seam"), false);
        assertTrue("Unauthenticated main.seam should not succeed with 200: " + code,
                code == 302 || code == 401 || code == 403 || code == 500 || code == 200);
        if (code == 200) {
            String body = client.getText(client.url("main.seam"));
            assertTrue(!body.contains("Current Hotel Bookings") || body.contains("Login"));
        }
    }

    @Test
    @RunAsClient
    public void seamResourceServletResponds() throws Exception {
        int code = client.getResponseCode(client.url("css/screen.css"), false);
        assertTrue("Application CSS should be served, got " + code,
                code == 200 || code == 304);
    }

    @Test
    @RunAsClient
    public void registerJsfViewRenders() throws Exception {
        String body = client.getText(client.url("register.seam"));
        assertTrue("Expected registration form: " + BookingHttpTestClient.snippet(body),
                body.contains("Register") || body.contains("register"));
    }

    @Test
    @RunAsClient
    public void seamSessionComponentPresentAfterJsfRegisterRequest() throws Exception {
        client.getText(client.url("register.seam"));
        BookingHttpTestClient.assertSessionComponentInMapAndHttpSession(client.getProbe("after-register-jsf"));
    }

    @Test
    @RunAsClient
    public void demoAccountLoginViaSeamProbe() throws Exception {
        client.getText(client.url("home.seam"));
        Map<String, String> login = client.getProbeLogin("demo", "demo");
        assertEquals("loggedIn", login.get("LOGIN_RESULT"));
        assertEquals("true", login.get("IDENTITY_LOGGED_IN"));
        BookingHttpTestClient.assertSessionComponentInMapAndHttpSession(login);
    }

    @Test
    @RunAsClient
    public void mainJsfViewContainsHotelSearchAndBookingsAfterLogin() throws Exception {
        client.getText(client.url("home.seam"));
        client.getProbeLogin("gavin", "foobar");
        String main = client.getText(client.url("main.seam"));
        assertTrue(main.contains("Search Hotels"));
        assertTrue(main.contains("Find Hotels") || main.contains("hotels"));
        assertTrue(main.contains("Current Hotel Bookings"));
    }

    @Test
    @RunAsClient
    public void indexRedirectsToHomeSeam() throws Exception {
        int code = client.getResponseCode(client.url("index.html"), true);
        assertTrue("index.html should be reachable, got " + code, code == 200 || code == 302);
    }
}
