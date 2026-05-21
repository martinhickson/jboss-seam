package org.jboss.seam.example.booking.test;

import static org.junit.Assert.assertEquals;
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

/**
 * HTTP client for {@code @RunAsClient} booking Seam/JSF Arquillian tests.
 */
final class BookingHttpTestClient {

    private final URL baseUrl;
    private CookieManager cookieManager;

    BookingHttpTestClient(URL baseUrl) {
        this.baseUrl = baseUrl;
    }

    void installCookieManager() {
        cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        CookieHandler.setDefault(cookieManager);
    }

    void clearCookieManager() {
        CookieHandler.setDefault(null);
        cookieManager = null;
    }

    URL url(String path) throws Exception {
        return new URL(baseUrl, path);
    }

    Map<String, String> getProbe(String phase) throws Exception {
        return parse(getText(url("probe/session?phase=" + phase)));
    }

    Map<String, String> getProbeLogin(String user, String pass) throws Exception {
        return parse(getText(url("probe/login?username=" + user + "&password=" + pass)));
    }

    String getText(URL url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setInstanceFollowRedirects(true);
        connection.connect();
        int code = connection.getResponseCode();
        InputStream stream = code >= 400 ? connection.getErrorStream() : connection.getInputStream();
        if (stream == null) {
            throw new IOException("HTTP " + code + " for " + url + " (no body)");
        }
        try (InputStream in = stream) {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            in.transferTo(body);
            if (code != 200) {
                throw new IOException("HTTP " + code + " for " + url + ": " + snippet(body.toString(StandardCharsets.UTF_8)));
            }
            return body.toString(StandardCharsets.UTF_8);
        } finally {
            connection.disconnect();
        }
    }

    int getResponseCode(URL url, boolean followRedirects) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setInstanceFollowRedirects(followRedirects);
        connection.connect();
        try {
            return connection.getResponseCode();
        } finally {
            connection.disconnect();
        }
    }

    static void assertSessionComponentInMapAndHttpSession(Map<String, String> probe) {
        assertEquals("probe missing SESSION_CONTEXT_ACTIVE: " + probe,
                "true", probe.get("SESSION_CONTEXT_ACTIVE"));
        assertTrue("REGISTRY_BEAN_CLASS: " + probe,
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

    static Map<String, String> parse(String body) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String line : body.split("\\R")) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                values.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
        }
        return values;
    }

    static String snippet(String body) {
        return body.length() > 200 ? body.substring(0, 200) + "..." : body;
    }
}
