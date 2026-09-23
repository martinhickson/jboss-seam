package org.jboss.seam.example.booking.test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.security.Identity;
import org.jboss.seam.servlet.ContextualHttpServletRequest;

/**
 * Authorization-code login against the PicketLink OIDC server.
 * Local username/password login stays available when this is switched off.
 */
public class HotelOidcServlet extends HttpServlet {

    static final String OIDC_SUBJECT = "oidcSubject";

    private static final long serialVersionUID = 1L;
    private static final String STATE = "oidcState";

    private final SecureRandom random = new SecureRandom();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String path = request.getServletPath();
        if (path != null && path.endsWith("/callback")) {
            callback(request, response);
            return;
        }
        start(request, response);
    }

    private void start(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String state = randomState();
        request.getSession(true).setAttribute(STATE, state);
        String authorize = trimSlash(param(request, "oidc.issuer")) + "/oidc/authorize"
                + "?response_type=code"
                + "&client_id=" + enc(param(request, "oidc.client.id"))
                + "&redirect_uri=" + enc(param(request, "oidc.redirect.uri"))
                + "&scope=" + enc("openid profile")
                + "&state=" + enc(state);
        response.sendRedirect(authorize);
    }

    private void callback(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        Object expected = session == null ? null : session.getAttribute(STATE);
        String state = request.getParameter("state");
        String code = request.getParameter("code");
        if (expected == null || !expected.equals(state) || code == null || code.isBlank()) {
            fail(request, response);
            return;
        }
        session.removeAttribute(STATE);
        try {
            String username = subjectFromCode(request, code);
            new ContextualHttpServletRequest(request) {
                @Override
                public void process() {
                    Contexts.getSessionContext().set(OIDC_SUBJECT, username);
                    Identity identity = Identity.instance();
                    identity.setUsername(username);
                    identity.login();
                }
            }.run();
            response.sendRedirect(request.getContextPath() + "/home.seam");
        } catch (Exception ex) {
            fail(request, response);
        }
    }

    private String subjectFromCode(HttpServletRequest request, String code) throws Exception {
        String issuer = trimSlash(param(request, "oidc.issuer"));
        String clientId = param(request, "oidc.client.id");
        String body = "grant_type=authorization_code"
                + "&code=" + enc(code)
                + "&redirect_uri=" + enc(param(request, "oidc.redirect.uri"))
                + "&client_id=" + enc(clientId)
                + "&client_secret=" + enc(param(request, "oidc.client.secret"));
        HttpResponse<String> token = http.send(HttpRequest.newBuilder(URI.create(issuer + "/oidc/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(Duration.ofSeconds(20))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(), HttpResponse.BodyHandlers.ofString());
        if (token.statusCode() != 200) {
            throw new IOException("token endpoint returned " + token.statusCode());
        }
        String idToken = jsonString(token.body(), "id_token");
        return verifiedSubject(issuer, clientId, idToken);
    }

    private String verifiedSubject(String issuer, String clientId, String idToken) throws Exception {
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new IOException("id_token is not a signed JWT");
        }
        String headerJson = new String(b64(parts[0]), StandardCharsets.UTF_8);
        String payloadJson = new String(b64(parts[1]), StandardCharsets.UTF_8);
        if (!"RS256".equals(jsonString(headerJson, "alg"))) {
            throw new IOException("id_token alg is not RS256");
        }
        RSAPublicKey key = rsaKey(issuer, jsonString(headerJson, "kid"));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        if (!signature.verify(b64(parts[2]))) {
            throw new IOException("id_token signature rejected");
        }
        if (!issuer.equals(jsonString(payloadJson, "iss"))) {
            throw new IOException("id_token issuer rejected");
        }
        if (!audienceContains(payloadJson, clientId)) {
            throw new IOException("id_token audience rejected");
        }
        long exp = jsonLong(payloadJson, "exp");
        if (exp <= System.currentTimeMillis() / 1000L) {
            throw new IOException("id_token expired");
        }
        String username = jsonString(payloadJson, "preferred_username");
        if (username == null || username.isBlank()) {
            username = jsonString(payloadJson, "sub");
        }
        if (username == null || username.isBlank()) {
            throw new IOException("id_token has no subject");
        }
        return username;
    }

    private RSAPublicKey rsaKey(String issuer, String kid) throws Exception {
        HttpResponse<String> jwks = http.send(HttpRequest.newBuilder(URI.create(issuer + "/oidc/jwks"))
                .timeout(Duration.ofSeconds(20))
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString());
        if (jwks.statusCode() != 200) {
            throw new IOException("jwks returned " + jwks.statusCode());
        }
        String body = jwks.body();
        int from = 0;
        if (kid != null && !kid.isBlank()) {
            int kidAt = body.indexOf("\"kid\":\"" + kid + "\"");
            if (kidAt < 0) {
                throw new IOException("jwks has no key " + kid);
            }
            from = body.lastIndexOf('{', kidAt);
        }
        int end = body.indexOf('}', from);
        String jwk = body.substring(from, end + 1);
        BigInteger modulus = new BigInteger(1, b64(jsonString(jwk, "n")));
        BigInteger exponent = new BigInteger(1, b64(jsonString(jwk, "e")));
        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    private static boolean audienceContains(String payload, String clientId) {
        int key = payload.indexOf("\"aud\"");
        if (key < 0) {
            return false;
        }
        int colon = payload.indexOf(':', key);
        int next = payload.indexOf(',', colon + 1);
        int arrayEnd = payload.indexOf(']', colon + 1);
        int stop = payload.length();
        if (next > colon && next < stop) {
            stop = next;
        }
        if (arrayEnd > colon && arrayEnd < stop) {
            stop = arrayEnd + 1;
        }
        return payload.substring(colon, stop).contains("\"" + clientId + "\"");
    }

    private void fail(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect(request.getContextPath() + "/home.seam?oidc=failed");
    }

    private String randomState() {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String param(HttpServletRequest request, String name) {
        String value = request.getServletContext().getInitParameter(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing context param " + name);
        }
        return value;
    }

    private static String trimSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String jsonString(String json, String name) {
        String marker = "\"" + name + "\"";
        int key = json.indexOf(marker);
        if (key < 0) {
            return null;
        }
        int colon = json.indexOf(':', key + marker.length());
        int start = json.indexOf('"', colon + 1);
        if (start < 0) {
            return null;
        }
        int end = start + 1;
        while (end < json.length()) {
            if (json.charAt(end) == '"' && json.charAt(end - 1) != '\\') {
                break;
            }
            end++;
        }
        return json.substring(start + 1, end);
    }

    private static long jsonLong(String json, String name) {
        String marker = "\"" + name + "\"";
        int key = json.indexOf(marker);
        int colon = json.indexOf(':', key + marker.length());
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) {
            end++;
        }
        return Long.parseLong(json.substring(start, end));
    }

    private static byte[] b64(String value) {
        return Base64.getUrlDecoder().decode(value);
    }
}
