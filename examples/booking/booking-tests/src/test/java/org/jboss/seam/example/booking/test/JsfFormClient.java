package org.jboss.seam.example.booking.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal HTTP client for JSF form GET/POST (ViewState, cookies) in Arquillian @RunAsClient tests.
 */
final class JsfFormClient {

    private static final Pattern INPUT_TAG =
            Pattern.compile("<input\\s+([^>]*?)/?>", Pattern.CASE_INSENSITIVE);
    private static final Pattern SELECT_TAG =
            Pattern.compile("<select\\s+([^>]*?)>(.*?)</select>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern OPTION_SELECTED =
            Pattern.compile("<option\\s+([^>]*?)selected[^>]*value=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern OPTION_FIRST =
            Pattern.compile("<option\\s+[^>]*value=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTR_NAME =
            Pattern.compile("\\bname=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTR_VALUE =
            Pattern.compile("\\bvalue=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTR_TYPE =
            Pattern.compile("\\btype=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern VIEW_STATE =
            Pattern.compile("name=[\"'](?:jakarta|javax)\\.faces\\.ViewState[\"'][^>]*value=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern VIEW_STATE_ALT =
            Pattern.compile("value=[\"']([^\"']+)[\"'][^>]*name=[\"'](?:jakarta|javax)\\.faces\\.ViewState[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern SELECT_HOTEL_LINK =
            Pattern.compile("href=[\"']([^\"']*selectHotel[^\"']*)[\"']", Pattern.CASE_INSENSITIVE);

    private final URL baseUrl;
    private String cookieHeader;

    JsfFormClient(URL baseUrl) {
        this.baseUrl = baseUrl;
    }

    JsfFormPage get(String resource) throws IOException {
        return request("GET", resource, null, true);
    }

    JsfFormPage postForm(String resource, Map<String, String> fields) throws IOException {
        return request("POST", resource, fields, true);
    }

    String getCookieHeader() {
        return cookieHeader;
    }

    void setCookieHeader(String cookieHeader) {
        this.cookieHeader = cookieHeader;
    }

    static JsfFormPage parseForm(String html, String formId) {
        Map<String, String> hidden = new LinkedHashMap<>();
        Map<String, String> fields = new LinkedHashMap<>();

        Matcher inputMatcher = INPUT_TAG.matcher(html);
        while (inputMatcher.find()) {
            String attrs = inputMatcher.group(1);
            String name = extractAttr(attrs, ATTR_NAME);
            if (name == null) {
                continue;
            }
            String type = extractAttr(attrs, ATTR_TYPE);
            if (type != null) {
                type = type.toLowerCase();
            }
            String value = extractAttr(attrs, ATTR_VALUE);
            if (value == null) {
                value = "";
            }

            if ("hidden".equals(type)) {
                hidden.put(name, value);
                continue;
            }
            if ("submit".equals(type) || "button".equals(type)) {
                continue;
            }
            if (name.startsWith(formId + ":") || name.startsWith("jakarta.faces.") || name.startsWith("javax.faces.")) {
                fields.put(name, value);
            }
        }

        Matcher selectMatcher = SELECT_TAG.matcher(html);
        while (selectMatcher.find()) {
            String attrs = selectMatcher.group(1);
            String name = extractAttr(attrs, ATTR_NAME);
            if (name == null || !name.startsWith(formId + ":")) {
                continue;
            }
            String body = selectMatcher.group(2);
            String value = null;
            Matcher selectedMatcher = OPTION_SELECTED.matcher(body);
            if (selectedMatcher.find()) {
                value = selectedMatcher.group(2);
            } else {
                Matcher firstMatcher = OPTION_FIRST.matcher(body);
                if (firstMatcher.find()) {
                    value = firstMatcher.group(1);
                }
            }
            if (value != null) {
                fields.put(name, value);
            }
        }

        JsfFormPage page = new JsfFormPage();
        page.body = html;
        page.formPrefix = formId;
        page.hiddenFields = hidden;
        page.fields = fields;
        page.viewState = hidden.get("jakarta.faces.ViewState");
        if (page.viewState == null) {
            page.viewState = hidden.get("javax.faces.ViewState");
        }
        if (page.viewState == null) {
            Matcher viewStateMatcher = VIEW_STATE.matcher(html);
            if (viewStateMatcher.find()) {
                page.viewState = viewStateMatcher.group(1);
                hidden.put("jakarta.faces.ViewState", page.viewState);
            } else {
                Matcher altMatcher = VIEW_STATE_ALT.matcher(html);
                if (altMatcher.find()) {
                    page.viewState = altMatcher.group(1);
                    hidden.put("jakarta.faces.ViewState", page.viewState);
                }
            }
        }
        return page;
    }

    static String findSelectHotelLink(String html) {
        Matcher matcher = SELECT_HOTEL_LINK.matcher(html);
        if (matcher.find()) {
            return matcher.group(1).replace("&amp;", "&");
        }
        return null;
    }

    Map<String, String> buildPostFields(JsfFormPage form, Map<String, String> overrides) {
        Map<String, String> post = new LinkedHashMap<>(form.hiddenFields);
        post.putAll(form.fields);
        if (overrides != null) {
            post.putAll(overrides);
        }
        if (form.viewState != null) {
            post.put("jakarta.faces.ViewState", form.viewState);
        }
        return post;
    }

    private static String extractAttr(String attrs, Pattern pattern) {
        Matcher matcher = pattern.matcher(attrs);
        return matcher.find() ? matcher.group(1) : null;
    }

    private URL resolveUrl(String resource) throws MalformedURLException {
        if (resource.startsWith("http://") || resource.startsWith("https://")) {
            return new URL(resource);
        }
        if (resource.startsWith("/")) {
            int port = baseUrl.getPort();
            if (port == -1) {
                port = "https".equals(baseUrl.getProtocol()) ? 443 : 80;
            }
            String path = resource;
            int semi = path.indexOf(';');
            if (semi > 0) {
                path = path.substring(0, semi);
            }
            return new URL(baseUrl.getProtocol(), baseUrl.getHost(), port, path);
        }
        return new URL(baseUrl, resource);
    }

    private JsfFormPage request(String method, String resource, Map<String, String> fields, boolean followRedirects)
            throws IOException {
        URL url = resolveUrl(resource);
        int redirects = 0;
        String currentMethod = method;
        Map<String, String> currentFields = fields;

        while (true) {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod(currentMethod);
            if (cookieHeader != null) {
                connection.setRequestProperty("Cookie", cookieHeader);
            }

            if ("POST".equals(currentMethod) && currentFields != null) {
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
                byte[] body = encodeForm(currentFields).getBytes(StandardCharsets.UTF_8);
                connection.setRequestProperty("Content-Length", String.valueOf(body.length));
                try (OutputStream out = connection.getOutputStream()) {
                    out.write(body);
                }
            }

            int status = connection.getResponseCode();
            cookieHeader = mergeCookies(cookieHeader, connection);

            if (followRedirects && status >= 300 && status < 400 && redirects < 10) {
                String location = connection.getHeaderField("Location");
                connection.disconnect();
                if (location == null || location.isEmpty()) {
                    break;
                }
                url = resolveRedirect(connection.getURL(), location);
                currentMethod = "GET";
                currentFields = null;
                redirects++;
                continue;
            }

            String body = readBody(connection);
            JsfFormPage page = new JsfFormPage();
            page.status = status;
            page.body = body;
            page.cookieHeader = cookieHeader;
            page.finalUrl = connection.getURL().toString();
            connection.disconnect();
            return page;
        }

        throw new IOException("Redirect loop exceeded");
    }

    private static URL resolveRedirect(URL requestUrl, String location) throws MalformedURLException {
        try {
            URI target = requestUrl.toURI().resolve(location);
            return target.toURL();
        } catch (Exception e) {
            throw new MalformedURLException(e.getMessage());
        }
    }

    private static String encodeForm(Map<String, String> fields) throws IOException {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
            sb.append('=');
            sb.append(URLEncoder.encode(entry.getValue() == null ? "" : entry.getValue(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    private static String readBody(HttpURLConnection connection) throws IOException {
        InputStream stream = connection.getResponseCode() >= 400
                ? connection.getErrorStream()
                : connection.getInputStream();
        if (stream == null) {
            return "";
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(line);
            }
            return sb.toString();
        }
    }

    private static String mergeCookies(String existing, HttpURLConnection connection) {
        Map<String, List<String>> headerFields = connection.getHeaderFields();
        if (headerFields == null) {
            return existing;
        }
        List<String> setCookies = headerFields.get("Set-Cookie");
        if (setCookies == null) {
            return existing;
        }
        Map<String, String> jar = new LinkedHashMap<>();
        if (existing != null) {
            for (String part : existing.split(";")) {
                String trimmed = part.trim();
                if (trimmed.contains("=")) {
                    jar.put(trimmed.substring(0, trimmed.indexOf('=')), trimmed.substring(trimmed.indexOf('=') + 1));
                }
            }
        }
        for (String setCookie : setCookies) {
            if (setCookie == null || !setCookie.contains("=")) {
                continue;
            }
            String pair = setCookie.split(";", 2)[0].trim();
            int eq = pair.indexOf('=');
            if (eq > 0) {
                jar.put(pair.substring(0, eq), pair.substring(eq + 1));
            }
        }
        if (jar.isEmpty()) {
            return existing;
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : jar.entrySet()) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return sb.toString();
    }

    static final class JsfFormPage {
        int status;
        String body;
        String cookieHeader;
        String finalUrl;
        String formPrefix;
        String viewState;
        Map<String, String> hiddenFields = new LinkedHashMap<>();
        Map<String, String> fields = new LinkedHashMap<>();
    }
}
