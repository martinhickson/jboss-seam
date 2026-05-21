package org.jboss.seam.jakarta.it.jandex;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Exercises anonymous session creation, Seam login, and optional session id rotation
 * ({@link jakarta.servlet.http.HttpServletRequest#changeSessionId()}), then probes
 * {@code org.jboss.seam.web.session} in the HttpSession.
 */
@RunWith(Arquillian.class)
public class SessionLoginWildFly36IT {

    private CookieManager cookieManager;

    @Deployment(testable = false)
    public static org.jboss.shrinkwrap.api.spec.WebArchive deploy() throws Exception {
        return org.jboss.seam.deployment.JandexScanWildFly36IT.createDeploymentArchive();
    }

    @ArquillianResource
    private URL baseUrl;

    @Before
    public void installCookieManager() {
        cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        CookieHandler.setDefault(cookieManager);
    }

    @After
    public void clearCookieManager() {
        CookieHandler.setDefault(null);
        cookieManager = null;
    }

    @Test
    @RunAsClient
    public void seamSessionComponentSurvivesLoginAndSessionIdRotation() throws Exception {
        Map<String, String> anonymous = get(probeUrl("anonymous"));
        assertEquals("true", anonymous.get("HTTP_SESSION_PRESENT"));
        assertEquals("false", anonymous.get("IDENTITY_LOGGED_IN"));
        assertSessionComponentInMapAndHttpSession(anonymous);

        Map<String, String> login = get(loginUrl(true));
        assertEquals("loggedIn", login.get("LOGIN_RESULT"));
        assertEquals("true", login.get("IDENTITY_LOGGED_IN"));
        assertSessionComponentInMapAndHttpSession(login);
        assertEquals("true", login.get("ROTATED_SESSION_ID"));
        assertNotEquals("", login.get("SESSION_ID_AFTER_ROTATE"));
        if (!login.get("SESSION_ID_BEFORE").isEmpty()) {
            assertNotEquals(login.get("SESSION_ID_BEFORE"), login.get("SESSION_ID_AFTER_ROTATE"));
        }

        Map<String, String> postLogin = get(probeUrl("post-login"));
        assertEquals("true", postLogin.get("HTTP_SESSION_PRESENT"));
        assertEquals("true", postLogin.get("IDENTITY_LOGGED_IN"));
        assertEquals("false", postLogin.get("SESSION_IS_INVALID"));
        assertEquals("true", postLogin.get("REQUESTED_EQUALS_SESSION_ID"));
        assertSessionComponentInMapAndHttpSession(postLogin);
    }

    @Test
    @RunAsClient
    public void seamSessionComponentSurvivesLoginWithoutSessionIdRotation() throws Exception {
        Map<String, String> anonymous = get(probeUrl("anonymous-no-rotate"));
        assertSessionComponentInMapAndHttpSession(anonymous);

        Map<String, String> login = get(loginUrl(false));
        assertEquals("loggedIn", login.get("LOGIN_RESULT"));
        assertSessionComponentInMapAndHttpSession(login);
        assertEquals("false", login.get("ROTATED_SESSION_ID"));

        Map<String, String> postLogin = get(probeUrl("post-login-no-rotate"));
        assertEquals("true", postLogin.get("IDENTITY_LOGGED_IN"));
        assertSessionComponentInMapAndHttpSession(postLogin);
    }

    /**
     * Production failure mode: registry has the component but
     * {@code ScopeType.SESSION.getContext().get("org.jboss.seam.web.session")} is null
     * while {@code HttpSession.getAttribute} may or may not be set.
     */
    private static void assertSessionComponentInMapAndHttpSession(Map<String, String> probe) {
        assertEquals("probe missing SESSION_CONTEXT_ACTIVE: " + probe,
                "true", probe.get("SESSION_CONTEXT_ACTIVE"));
        assertTrue("REGISTRY_BEAN_CLASS missing: " + probe,
                probe.get("REGISTRY_BEAN_CLASS").contains("org.jboss.seam.web.Session"));
        assertEquals("HAS_SEAM_SESSION_KEY: " + probe, "true", probe.get("HAS_SEAM_SESSION_KEY"));
        assertEquals("HAS_MAP_KEY: " + probe, "true", probe.get("HAS_MAP_KEY"));
        assertEquals("MAP_EQUALS_HTTPSESSION: " + probe, "true", probe.get("MAP_EQUALS_HTTPSESSION"));
        assertTrue("MAP_VALUE_CLASS: " + probe,
                probe.get("MAP_VALUE_CLASS").contains("org.jboss.seam.web.Session"));
        assertEquals(probe.get("HTTPSESSION_VALUE_CLASS"), probe.get("MAP_VALUE_CLASS"));
        assertEquals("SESSION_GETINSTANCE_PRESENT: " + probe,
                "true", probe.get("SESSION_GETINSTANCE_PRESENT"));
    }

    private URL probeUrl(String phase) throws Exception {
        return new URL(baseUrl, "session-probe?phase=" + phase);
    }

    private URL loginUrl(boolean rotateSessionId) throws Exception {
        return new URL(baseUrl,
                "login-probe?username=testuser&password=secret&rotateSessionId=" + rotateSessionId);
    }

    private Map<String, String> get(URL url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setInstanceFollowRedirects(true);
        connection.connect();
        try (InputStream stream = connection.getInputStream()) {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            stream.transferTo(body);
            assertEquals("HTTP " + connection.getResponseCode() + " for " + url,
                    200, connection.getResponseCode());
            return parseKeyValues(body.toString(StandardCharsets.UTF_8));
        } finally {
            connection.disconnect();
        }
    }

    static Map<String, String> parseKeyValues(String body) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String line : body.split("\\R")) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                values.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
        }
        return values;
    }
}
