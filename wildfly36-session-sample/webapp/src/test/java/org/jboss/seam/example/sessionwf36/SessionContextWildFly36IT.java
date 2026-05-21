package org.jboss.seam.example.sessionwf36;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.cxf.common.security.GroupPrincipal;
import org.dom4j.DocumentException;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.el.util.ReflectionUtil;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;

import javassist.util.proxy.MethodFilter;

@RunWith(Arquillian.class)
public class SessionContextWildFly36IT {

    @Deployment(testable = false)
    public static WebArchive createDeployment() throws Exception {
        File seamLibrary = new File(org.jboss.seam.servlet.SeamListener.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File javassistLibrary = new File(MethodFilter.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File jandexLibrary = new File(org.jboss.jandex.Indexer.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File cxfCoreLibrary = new File(GroupPrincipal.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File dom4jLibrary = new File(DocumentException.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File jbossElLibrary = new File(ReflectionUtil.class.getProtectionDomain().getCodeSource().getLocation().toURI());

        File webInf = new File("src/main/webapp/WEB-INF");
        File jandexIndex = new File("target/classes/META-INF/jandex.idx");
        File enhancedLibJar = resolveEnhancedSeamLibJar();

        return ShrinkWrap.create(WebArchive.class, "seam-session-wf36-it.war")
                .addClasses(
                        SessionCounter.class,
                        JsfSessionBean.class,
                        SessionProbeServlet.class,
                        LibJarProbeServlet.class,
                        ProbeDependency.class,
                        ConversationCounter.class,
                        ApplicationCounter.class,
                        CoreSeamProbeServlet.class,
                        BijectionAction.class,
                        OutjectionAction.class,
                        SessionEventsState.class,
                        ConversationJsfBean.class,
                        SampleAuthenticator.class,
                        ProtectedAction.class)
                .addAsLibraries(seamLibrary, javassistLibrary, jandexLibrary, dom4jLibrary, cxfCoreLibrary, jbossElLibrary)
                .addAsLibraries(enhancedLibJar)
                .addAsWebInfResource(new File(webInf, "web.xml"), "web.xml")
                .addAsWebInfResource(new File(webInf, "components.xml"), "components.xml")
                .addAsWebInfResource(new File(webInf, "faces-config.xml"), "faces-config.xml")
                .addAsWebInfResource(new File(webInf, "beans.xml"), "beans.xml")
                .addAsWebInfResource(new File(webInf, "pages.xml"), "pages.xml")
                .addAsWebResource(new File("src/main/webapp/home.xhtml"))
                .addAsWebResource(new File("src/main/webapp/conversation.xhtml"))
                .addAsWebResource(new File("src/main/webapp/login.xhtml"))
                .addAsWebResource(new File("src/main/webapp/protected.xhtml"))
                .addAsWebResource(new File("src/main/webapp/admin.xhtml"))
                .addAsWebResource(new File("src/main/webapp/security-denied.xhtml"))
                .addAsResource("seam.properties")
                .addAsResource(jandexIndex, "META-INF/jandex.idx");
    }

    @ArquillianResource
    private URL baseUrl;

    @Test
    @RunAsClient
    public void libJar_enhancedSeamSessionInstallsFromWebInfLib() throws Exception {
        CoreProbeResult first = getCoreProbeWithSession("/probe/lib/enhanced", null);
        assertEquals("Lib jar probe failed: " + first.values, "PASS", first.values.get("OVERALL"));
        assertEquals("true", first.values.get("SESSION_CONTEXT"));
        assertEquals("true", first.values.get("IN_REGISTRY"));
        assertEquals("true", first.values.get("MAP_IS_SET"));
        assertTrue("MAP_VALUE_CLASS must be lib override: " + first.values,
                first.values.get("MAP_VALUE_CLASS").contains("EnhancedSeamSession"));
        assertTrue("HttpSession attribute class must be lib override: " + first.values,
                first.values.get("HTTPSESSION_VALUE_CLASS").contains("EnhancedSeamSession"));
        assertTrue("Registry bean class must be lib override: " + first.values,
                first.values.get("REGISTRY_BEAN_CLASS").contains("EnhancedSeamSession"));
        assertEquals("true", first.values.get("HTTPSESSION_HAS_KEY"));
        assertEquals("true", first.values.get("MAP_MATCHES_HTTPSESSION"));
        assertEquals("true", first.values.get("MAP_MATCHES_GETINSTANCE"));
        assertTrue("SESSION_CONTEXT_KEYS must include component name: " + first.values.get("SESSION_CONTEXT_KEYS"),
                first.values.get("SESSION_CONTEXT_KEYS").contains("org.jboss.seam.web.session"));
        assertTrue("HTTPSESSION_KEYS must include component name: " + first.values.get("HTTPSESSION_KEYS"),
                first.values.get("HTTPSESSION_KEYS").contains("org.jboss.seam.web.session"));
        assertEquals("true", first.values.get("INSTALLED"));
        assertTrue(first.values.get("GETINSTANCE_CLASS").contains("EnhancedSeamSession"));
        assertEquals("WEB-INF/lib", first.values.get("SOURCE"));
        assertEquals(1, Integer.parseInt(first.values.get("LIB_HITS")));
        assertNotNull("HttpSession cookie required for session-scoped lib component", first.cookieHeader);

        CoreProbeResult second = getCoreProbeWithSession("/probe/lib/enhanced", first.cookieHeader);
        assertEquals("PASS", second.values.get("OVERALL"));
        assertEquals(2, Integer.parseInt(second.values.get("LIB_HITS")));
    }

    @Test
    @RunAsClient
    public void rawRequest_hasNoSeamSessionContext() throws Exception {
        ProbeResult result = getProbe("/probe/raw", null);
        assertFalse("Raw servlet must not activate Seam session context: " + result.body, result.sessionContext);
        assertEquals(0, result.componentHits);
    }

    @Test
    @RunAsClient
    public void manualLifecycle_bindsSessionContext() throws Exception {
        ProbeResult result = getProbe("/probe/manual", null);
        assertTrue("Manual ServletLifecycle should bind session context: " + result.body, result.sessionContext);
        assertTrue("Manual lifecycle should bind event context: " + result.body, result.eventContext);
        assertTrue("Session-scoped component should increment: " + result.body, result.componentHits >= 1);
    }

    @Test
    @RunAsClient
    public void contextualServlet_bindsSessionContext() throws Exception {
        ProbeResult result = getProbe("/probe/servlet", null);
        assertTrue("ContextualHttpServletRequest should bind session context: " + result.body, result.sessionContext);
        assertTrue(result.componentHits >= 1);
        assertNotNull("HttpSession should exist after contextual request", result.httpSessionId);
    }

    @Test
    @RunAsClient
    public void sessionScopedComponentPersistsAcrossHttpRequests() throws Exception {
        ProbeResult first = getProbe("/probe/servlet?marker=alpha", null);
        assertTrue(first.sessionContext);
        assertEquals(1, first.componentHits);
        assertNotNull(first.cookieHeader);

        ProbeResult second = getProbe("/probe/servlet", first.cookieHeader);
        assertTrue("Second request should still have session context: " + second.body, second.sessionContext);
        assertEquals("Session-scoped hits should accumulate via HttpSession", 2, second.componentHits);
        assertEquals("Session attribute should survive", "alpha", second.contextMarker);
        assertEquals("Same HTTP session", first.httpSessionId, second.httpSessionId);
    }

    @Test
    @RunAsClient
    public void conversation_propagatesCidAndRetainsState() throws Exception {
        CoreProbeResult start = getCoreProbeWithSession("/core/conversation/start?signal=alpha", null);
        assertEquals("PASS", start.values.get("OVERALL"));
        assertEquals("start", start.values.get("ACTION"));
        assertEquals("true", start.values.get("LONG_RUNNING"));
        assertEquals("alpha", start.values.get("LAST_SIGNAL"));
        assertEquals("dep-ok", start.values.get("DEPENDENCY"));
        assertNotNull(start.values.get("CID"));
        assertFalse(start.values.get("CID").isEmpty());
        assertNotNull("Conversation entries require HttpSession cookie", start.cookieHeader);

        String cidParameter = start.values.get("CID_PARAMETER");
        String cid = start.values.get("CID");
        int startSteps = Integer.parseInt(start.values.get("STEPS"));
        assertTrue(startSteps > 0);

        String stepPath = "/core/conversation/step?" + cidParameter + "=" + cid + "&signal=beta";
        CoreProbeResult step = getCoreProbeWithSession(stepPath, start.cookieHeader);
        assertEquals("PASS", step.values.get("OVERALL"));
        assertEquals("step", step.values.get("ACTION"));
        assertEquals(cid, step.values.get("CID"));
        assertEquals("true", step.values.get("LONG_RUNNING"));
        assertEquals(startSteps + 1, Integer.parseInt(step.values.get("STEPS")));
        assertEquals("beta", step.values.get("LAST_SIGNAL"));

        String endPath = "/core/conversation/end?" + cidParameter + "=" + cid + "&signal=omega";
        CoreProbeResult end = getCoreProbeWithSession(endPath, start.cookieHeader);
        assertEquals("PASS", end.values.get("OVERALL"));
        assertEquals("end", end.values.get("ACTION"));
        assertEquals(cid, end.values.get("CID"));
        assertEquals("true", end.values.get("ENDED"));
        assertEquals("false", end.values.get("LONG_RUNNING"));
        assertEquals(startSteps + 2, Integer.parseInt(end.values.get("STEPS")));
        assertEquals("omega", end.values.get("LAST_SIGNAL"));
    }

    @Test
    @RunAsClient
    public void applicationScopedComponentPersistsAcrossRequests() throws Exception {
        CoreProbeResult first = getCoreProbeWithSession("/core/application", null);
        assertEquals("PASS", first.values.get("OVERALL"));
        int firstHits = Integer.parseInt(first.values.get("APPLICATION_HITS"));
        assertTrue(firstHits > 0);

        CoreProbeResult second = getCoreProbeWithSession("/core/application", first.cookieHeader);
        assertEquals("PASS", second.values.get("OVERALL"));
        assertEquals(firstHits + 1, Integer.parseInt(second.values.get("APPLICATION_HITS")));
    }

    @Test
    @RunAsClient
    public void bijectionAndEvents_workUnderContextualServlet() throws Exception {
        CoreProbeResult result = getCoreProbeWithSession("/core/bijection", null);
        assertEquals("PASS", result.values.get("OVERALL"));
        assertEquals("true", result.values.get("CONTEXT_EVENT"));
        assertEquals("true", result.values.get("CONTEXT_SESSION"));
        assertEquals("dep-ok", result.values.get("BIJECTION"));
        assertEquals("event-ok", result.values.get("EVENT"));
    }

    @Test
    @RunAsClient
    public void outjectionAndObserver_workUnderContextualServlet() throws Exception {
        CoreProbeResult result = getCoreProbeWithSession("/core/outjection?signal=alpha", null);
        assertEquals("PASS", result.values.get("OVERALL"));
        assertEquals("dep-ok:alpha", result.values.get("RESULT"));
        assertEquals("out-alpha", result.values.get("OUTJECTION"));
        assertEquals("alpha-event", result.values.get("OBSERVED"));
    }

    @Test
    @RunAsClient
    public void sessionScopeWithEvents_accumulatesAcrossRequests() throws Exception {
        CoreProbeResult first = getCoreProbeWithSession("/core/scopes?signal=one", null);
        assertEquals("PASS", first.values.get("OVERALL"));
        assertEquals("1", first.values.get("SESSION_HITS"));
        assertEquals("one", first.values.get("LAST_SIGNAL"));

        CoreProbeResult second = getCoreProbeWithSession("/core/scopes?signal=two", first.cookieHeader);
        assertEquals("PASS", second.values.get("OVERALL"));
        assertEquals("2", second.values.get("SESSION_HITS"));
        assertEquals("two", second.values.get("LAST_SIGNAL"));
    }

    @Test
    @RunAsClient
    public void identity_statusIsNotLoggedInInitially() throws Exception {
        CoreProbeResult result = getCoreProbeWithSession("/core/identity/status", null);
        assertEquals("PASS", result.values.get("OVERALL"));
        assertEquals("false", result.values.get("LOGGED_IN"));
    }

    @Test
    @RunAsClient
    public void identity_loginSucceedsWithValidCredentials() throws Exception {
        CoreProbeResult result = getCoreProbeWithSession(
                "/core/identity/login?username=demo&password=secret", null);
        assertEquals("PASS", result.values.get("OVERALL"));
        assertEquals("true", result.values.get("LOGGED_IN"));
        assertEquals("loggedIn", result.values.get("LOGIN_RESULT"));
        assertEquals("demo", result.values.get("USERNAME"));
        assertEquals("true", result.values.get("HAS_ROLE_USER"));
        assertEquals("true", result.values.get("HAS_ROLE_ADMIN"));
    }

    @Test
    @RunAsClient
    public void identity_loginFailsWithInvalidCredentials() throws Exception {
        CoreProbeResult result = getCoreProbeWithSession(
                "/core/identity/login?username=demo&password=wrong", null);
        assertEquals("PASS", result.values.get("OVERALL"));
        assertEquals("false", result.values.get("LOGGED_IN"));
        assertEquals("failed", result.values.get("LOGIN_RESULT"));
    }

    @Test
    @RunAsClient
    public void identity_logoutClearsAuthentication() throws Exception {
        CoreProbeResult login = getCoreProbeWithSession(
                "/core/identity/login?username=demo&password=secret", null);
        assertEquals("true", login.values.get("LOGGED_IN"));

        CoreProbeResult logout = getCoreProbeWithSession("/core/identity/logout", login.cookieHeader);
        assertEquals("PASS", logout.values.get("OVERALL"));
        assertEquals("false", logout.values.get("LOGGED_IN"));
        assertEquals("loggedOut", logout.values.get("LOGIN_RESULT"));
    }

    @Test
    @RunAsClient
    public void restrict_blocksUnauthenticatedGreeting() throws Exception {
        CoreProbeResult result = getCoreProbeWithSession("/core/restrict/greeting", null);
        assertEquals("PASS", result.values.get("OVERALL"));
        assertEquals("NOT_LOGGED_IN", result.values.get("OUTCOME"));
    }

    @Test
    @RunAsClient
    public void restrict_allowsGreetingWhenLoggedIn() throws Exception {
        CoreProbeResult login = getCoreProbeWithSession(
                "/core/identity/login?username=demo&password=secret", null);
        assertEquals("true", login.values.get("LOGGED_IN"));

        CoreProbeResult result = getCoreProbeWithSession("/core/restrict/greeting", login.cookieHeader);
        assertEquals("PASS", result.values.get("OVERALL"));
        assertEquals("OK", result.values.get("OUTCOME"));
        assertEquals("protected:demo", result.values.get("RESULT"));
    }

    @Test
    @RunAsClient
    public void restrict_blocksAdminMethodForGuestRole() throws Exception {
        CoreProbeResult login = getCoreProbeWithSession(
                "/core/identity/login?username=guest&password=guest", null);
        assertEquals("true", login.values.get("LOGGED_IN"));

        CoreProbeResult result = getCoreProbeWithSession("/core/restrict/admin", login.cookieHeader);
        assertEquals("NOT_AUTHORIZED", result.values.get("OUTCOME"));
    }

    @Test
    @RunAsClient
    public void jsfLoginForm_postLogsInAndRedirectsToProtected() throws Exception {
        JsfFormClient client = new JsfFormClient(baseUrl);
        JsfFormClient.JsfFormPage loginGet = client.get("login.xhtml");
        assertEquals(200, loginGet.status);
        JsfFormClient.JsfFormPage loginForm = JsfFormClient.parseLoginForm(loginGet.body);
        assertNotNull(
                "Expected jakarta.faces.ViewState in login form (see target/login-get.html if missing)",
                loginForm.viewState);

        JsfFormClient.JsfFormPage afterLogin = client.submitLoginForm(loginForm, "demo", "secret");
        assertTrue(
                "Expected protected page after JSF login but got status=" + afterLogin.status
                        + " url=" + afterLogin.finalUrl + " body=" + afterLogin.body,
                afterLogin.status == 200 && afterLogin.body.contains("Protected page"));
        assertTrue(afterLogin.body.contains("protected:demo"));
        assertTrue(afterLogin.body.contains("Logged in as: demo"));
    }

    @Test
    @RunAsClient
    public void jsfLoginForm_postRejectsInvalidCredentials() throws Exception {
        JsfFormClient client = new JsfFormClient(baseUrl);
        JsfFormClient.JsfFormPage loginGet = client.get("login.xhtml");
        JsfFormClient.JsfFormPage loginForm = JsfFormClient.parseLoginForm(loginGet.body);

        JsfFormClient.JsfFormPage afterLogin = client.submitLoginForm(loginForm, "demo", "wrong");
        assertTrue(
                "Expected to remain on login page after bad password: " + afterLogin.body,
                afterLogin.body.contains("<h1>Login</h1>"));
        assertFalse("Should not reach protected page", afterLogin.body.contains("Protected page"));
    }

    @Test
    @RunAsClient
    public void jsfLoginPage_renders() throws Exception {
        JsfPageResult page = getJsfPage("login.xhtml", null, null);
        assertEquals(200, page.status);
        assertTrue(page.body.contains("Login"));
        assertTrue(page.body.contains("loginButton"));
    }

    @Test
    @RunAsClient
    public void jsfProtectedPage_redirectsToLoginWhenAnonymous() throws Exception {
        JsfPageResult page = getJsfPage("protected.xhtml", null, null);
        assertEquals(200, page.status);
        assertTrue("Expected login page but got: " + page.body, page.body.contains("<h1>Login</h1>"));
    }

    @Test
    @RunAsClient
    public void jsfProtectedPage_rendersAfterServletLogin() throws Exception {
        CoreProbeResult login = getCoreProbeWithSession(
                "/core/identity/login?username=demo&password=secret", null);
        JsfPageResult page = getJsfPage("protected.xhtml", login.cookieHeader, null);
        assertEquals(200, page.status);
        assertTrue(page.body.contains("Protected page"));
        assertTrue(page.body.contains("protected:demo"));
        assertTrue(page.body.contains("Logged in as: demo"));
    }

    @Test
    @RunAsClient
    public void jsfAdminPage_deniedForGuestUser() throws Exception {
        CoreProbeResult login = getCoreProbeWithSession(
                "/core/identity/login?username=guest&password=guest", null);
        JsfPageResult page = getJsfPage("admin.xhtml", login.cookieHeader, null);
        assertEquals(200, page.status);
        assertTrue(page.body.contains("Access denied"));
    }

    @Test
    @RunAsClient
    public void jsfAdminPage_rendersForAdminUser() throws Exception {
        CoreProbeResult login = getCoreProbeWithSession(
                "/core/identity/login?username=demo&password=secret", null);
        JsfPageResult page = getJsfPage("admin.xhtml", login.cookieHeader, null);
        assertEquals(200, page.status);
        assertTrue(page.body.contains("Admin page"));
        assertTrue(page.body.contains("admin-ok"));
    }

    @Test
    @RunAsClient
    public void jsfConversation_retainsStepsAcrossViews() throws Exception {
        JsfPageResult first = getJsfPage("conversation.xhtml", null, null);
        assertTrue("First JSF conversation view failed: " + first.body, first.status == 200);
        assertTrue(first.body.contains("JSF conversation steps:"));
        int firstSteps = extractConversationSteps(first.body);
        assertEquals(1, firstSteps);
        assertNotNull("JSF view should expose a conversation id", first.conversationId);

        String query = "conversationId=" + URLEncoder.encode(first.conversationId, StandardCharsets.UTF_8);
        JsfPageResult second = getJsfPage("conversation.xhtml", first.cookieHeader, query);
        assertTrue(
                "Second JSF conversation view failed: status=" + second.status + " body=" + second.body,
                second.status == 200);
        int secondSteps = extractConversationSteps(second.body);
        assertEquals("Conversation-scoped bean should increment in same conversation", firstSteps + 1, secondSteps);
    }

    @Test
    @RunAsClient
    public void jsfPage_canRenderSessionBean() throws Exception {
        URL pageUrl = new URL(baseUrl, "home.xhtml");
        HttpURLConnection connection = (HttpURLConnection) pageUrl.openConnection();
        connection.setInstanceFollowRedirects(true);
        int status = connection.getResponseCode();
        String body = readBody(connection);
        assertTrue("Expected 200 from JSF page but got " + status + ": " + body, status == 200);
        assertTrue("JSF page should render session hit count: " + body, body.contains("JSF session hits:"));
    }

    /** Match only the probe line we render, not conversationId inside javax.faces.ViewState. */
    private static final Pattern CONVERSATION_ID = Pattern.compile("<p>conversationId=([^<]+)</p>");
    private static final Pattern CONVERSATION_STEPS = Pattern.compile("JSF conversation steps:\\s*(\\d+)");

    private JsfPageResult getJsfPage(String path, String cookieHeader, String query) throws Exception {
        String resource = path.startsWith("/") ? path.substring(1) : path;
        if (query != null && !query.isEmpty()) {
            resource += resource.contains("?") ? "&" + query : "?" + query;
        }
        URL pageUrl = new URL(baseUrl, resource);
        HttpURLConnection connection = (HttpURLConnection) pageUrl.openConnection();
        connection.setInstanceFollowRedirects(true);
        if (cookieHeader != null) {
            connection.setRequestProperty("Cookie", cookieHeader);
        }
        int status = connection.getResponseCode();
        String body = readBody(connection);

        String setCookie = connection.getHeaderField("Set-Cookie");
        String newCookie = cookieHeader;
        if (setCookie != null && setCookie.contains("JSESSIONID")) {
            int semi = setCookie.indexOf(';');
            newCookie = semi > 0 ? setCookie.substring(0, semi) : setCookie;
        }

        Matcher matcher = CONVERSATION_ID.matcher(body);
        String conversationId = matcher.find() ? matcher.group(1) : null;

        JsfPageResult result = new JsfPageResult();
        result.status = status;
        result.body = body;
        result.cookieHeader = newCookie;
        result.conversationId = conversationId;
        return result;
    }

    private static int extractConversationSteps(String body) {
        Matcher matcher = CONVERSATION_STEPS.matcher(body);
        if (!matcher.find()) {
            return -1;
        }
        return Integer.parseInt(matcher.group(1));
    }

    private static File resolveEnhancedSeamLibJar() {
        File libTarget = new File("../enhanced-seam-lib/target");
        File[] jars = libTarget.listFiles((dir, name) ->
                name.startsWith("wildfly36-session-enhanced-lib-")
                        && name.endsWith(".jar")
                        && !name.contains("-sources")
                        && !name.contains("-javadoc"));
        if (jars == null || jars.length == 0) {
            throw new IllegalStateException(
                    "Missing enhanced-seam-lib JAR under " + libTarget.getAbsolutePath()
                            + " — run mvn package from wildfly36-session-sample first");
        }
        return jars[0];
    }

    private CoreProbeResult getCoreProbeWithSession(String path, String cookieHeader) throws Exception {
        URL url = new URL(baseUrl, path.startsWith("/") ? path.substring(1) : path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        if (cookieHeader != null) {
            connection.setRequestProperty("Cookie", cookieHeader);
        }
        int status = connection.getResponseCode();
        String body = readBody(connection);
        assertEquals("Core probe failed: " + body, 200, status);

        String setCookie = connection.getHeaderField("Set-Cookie");
        String newCookie = cookieHeader;
        if (setCookie != null && setCookie.contains("JSESSIONID")) {
            int semi = setCookie.indexOf(';');
            newCookie = semi > 0 ? setCookie.substring(0, semi) : setCookie;
        }

        CoreProbeResult result = new CoreProbeResult();
        result.values = parseKeyValues(body);
        result.cookieHeader = newCookie;
        return result;
    }

    private ProbeResult getProbe(String path, String cookieHeader) throws Exception {
        URL url = new URL(baseUrl, path.startsWith("/") ? path.substring(1) : path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        if (cookieHeader != null) {
            connection.setRequestProperty("Cookie", cookieHeader);
        }
        int status = connection.getResponseCode();
        String body = readBody(connection);
        assertEquals("Probe failed: " + body, 200, status);

        Map<String, String> values = parseKeyValues(body);
        String setCookie = connection.getHeaderField("Set-Cookie");
        String jsessionId = values.get("HTTP_SESSION_ID");
        if ("null".equals(jsessionId)) {
            jsessionId = null;
        }

        String newCookie = cookieHeader;
        if (setCookie != null && setCookie.contains("JSESSIONID")) {
            int semi = setCookie.indexOf(';');
            newCookie = semi > 0 ? setCookie.substring(0, semi) : setCookie;
        }

        ProbeResult result = new ProbeResult();
        result.body = body;
        result.eventContext = Boolean.parseBoolean(values.get("EVENT_CONTEXT"));
        result.sessionContext = Boolean.parseBoolean(values.get("SESSION_CONTEXT"));
        result.componentHits = Integer.parseInt(values.get("COMPONENT_HITS"));
        result.contextMarker = values.get("CONTEXT_MARKER");
        if ("null".equals(result.contextMarker)) {
            result.contextMarker = null;
        }
        result.httpSessionId = jsessionId;
        result.cookieHeader = newCookie;
        return result;
    }

    private static String readBody(HttpURLConnection connection) throws Exception {
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

    private static Map<String, String> parseKeyValues(String body) {
        Map<String, String> map = new HashMap<String, String>();
        for (String line : body.split("\n")) {
            int eq = line.indexOf('=');
            if (eq > 0) {
                map.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
        return map;
    }

    private static final class ProbeResult {
        String body;
        boolean eventContext;
        boolean sessionContext;
        int componentHits;
        String contextMarker;
        String httpSessionId;
        String cookieHeader;
    }

    private static final class CoreProbeResult {
        Map<String, String> values;
        String cookieHeader;
    }

    private static final class JsfPageResult {
        int status;
        String body;
        String cookieHeader;
        String conversationId;
    }
}
