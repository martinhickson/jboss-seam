package org.jboss.seam.deployment;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.cxf.common.security.GroupPrincipal;
import org.jboss.el.util.ReflectionUtil;
import org.dom4j.DocumentException;
import javassist.util.proxy.MethodFilter;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.jandex.Index;
import org.jboss.jandex.Indexer;
import org.jboss.jandex.IndexWriter;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.seam.deployment.JandexScanSupport;
import org.jboss.seam.deployment.PhaseFourFeatureServlet;
import org.jboss.seam.deployment.PhaseOneFeatureServlet;
import org.jboss.seam.deployment.PhaseThreeFeatureServlet;
import org.jboss.seam.deployment.PhaseTwoFeatureServlet;
import org.jboss.seam.jakarta.it.jandex.ScannedSeamComponent;
import org.jboss.seam.jakarta.it.jandex.PhaseFourAction;
import org.jboss.seam.jakarta.it.jandex.JsfPageOneBean;
import org.jboss.seam.jakarta.it.jandex.JsfPageTwoBean;
import org.jboss.seam.jakarta.it.jandex.PhaseOneAction;
import org.jboss.seam.jakarta.it.jandex.PhaseOneDependency;
import org.jboss.seam.jakarta.it.jandex.PhaseThreeApplicationState;
import org.jboss.seam.jakarta.it.jandex.PhaseThreeSessionState;
import org.jboss.seam.jakarta.it.jandex.PhaseTwoConversationState;
import org.jboss.seam.jakarta.it.jandex.PlainPojo;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.ByteArrayAsset;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
public class JandexScanWildFly36IT {

    @Deployment(testable = false)
    public static WebArchive deploy() throws Exception {
        File seamLibrary = new File(AbstractScanner.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File jandexLibrary = new File(Indexer.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File javassistLibrary = new File(MethodFilter.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File dom4jLibrary = new File(DocumentException.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File cxfCoreLibrary = new File(GroupPrincipal.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File jbossElLibrary = new File(ReflectionUtil.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        return ShrinkWrap.create(WebArchive.class, "jandex-scan-example.war")
                .addClasses(
                        ScannedSeamComponent.class,
                        PlainPojo.class,
                        PhaseOneAction.class,
                        PhaseOneDependency.class,
                        PhaseFourAction.class,
                        PhaseThreeApplicationState.class,
                        PhaseThreeSessionState.class,
                        PhaseTwoConversationState.class,
                        JsfPageOneBean.class,
                        JsfPageTwoBean.class,
                        JandexScanSupport.class,
                        ScannerProbeServlet.class,
                        PhaseFourFeatureServlet.class,
                        PhaseOneFeatureServlet.class,
                        PhaseThreeFeatureServlet.class,
                        PhaseTwoFeatureServlet.class,
                        PageFlowServlet.class)
                .addAsLibraries(seamLibrary, jandexLibrary, javassistLibrary, dom4jLibrary, cxfCoreLibrary, jbossElLibrary)
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml")
                .addAsWebInfResource("WEB-INF/components.xml", "components.xml")
                .addAsWebResource("pages/page1.xhtml", "pages/page1.xhtml")
                .addAsWebResource("pages/page2.xhtml", "pages/page2.xhtml")
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsResource(new ByteArrayAsset(createDeploymentIndex()), "META-INF/jandex.idx")
                .addAsResource("META-INF/seam.properties", "META-INF/seam.properties");
    }

    private static byte[] createDeploymentIndex() throws IOException {
        Indexer indexer = new Indexer();
        indexClass(indexer, ScannedSeamComponent.class);
        indexClass(indexer, PlainPojo.class);
        indexClass(indexer, PhaseOneAction.class);
        indexClass(indexer, PhaseOneDependency.class);
        indexClass(indexer, PhaseFourAction.class);
        indexClass(indexer, PhaseThreeApplicationState.class);
        indexClass(indexer, PhaseThreeSessionState.class);
        indexClass(indexer, PhaseTwoConversationState.class);
        indexClass(indexer, JsfPageOneBean.class);
        indexClass(indexer, JsfPageTwoBean.class);
        indexClass(indexer, JandexScanSupport.class);
        indexClass(indexer, ScannerProbeServlet.class);
        indexClass(indexer, PhaseFourFeatureServlet.class);
        indexClass(indexer, PhaseOneFeatureServlet.class);
        indexClass(indexer, PhaseThreeFeatureServlet.class);
        indexClass(indexer, PhaseTwoFeatureServlet.class);
        indexClass(indexer, PageFlowServlet.class);
        Index index = indexer.complete();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        IndexWriter writer = new IndexWriter(output);
        writer.write(index);
        return output.toByteArray();
    }

    private static void indexClass(Indexer indexer, Class<?> clazz) throws IOException {
        String resourceName = clazz.getName().replace('.', '/') + ".class";
        InputStream stream = clazz.getClassLoader().getResourceAsStream(resourceName);
        if (stream == null) {
            throw new IllegalStateException("Missing class resource: " + resourceName);
        }
        try (InputStream indexedStream = stream) {
            indexer.index(indexedStream);
        }
    }

    @ArquillianResource
    private URL baseUrl;

    @Test
    @RunAsClient
    public void shouldFindNameAnnotationViaJandexBackedScanner() throws Exception {
        URL probeUrl = new URL(baseUrl, "probe");
        try (InputStream stream = probeUrl.openStream()) {
            String body = new String(stream.readAllBytes(), StandardCharsets.UTF_8).trim();
            assertEquals("FOUND", body);
        }
    }

    @Test
    @RunAsClient
    public void shouldNotFindNameAnnotationOnPlainPojo() throws Exception {
        URL probeUrl = new URL(baseUrl, "probe?target=missing");
        try (InputStream stream = probeUrl.openStream()) {
            String body = new String(stream.readAllBytes(), StandardCharsets.UTF_8).trim();
            assertEquals("MISSING", body);
        }
    }

    @Test
    @RunAsClient
    public void shouldVerifySeamPhaseOneFeatureProbe() throws Exception {
        URL phaseOneUrl = new URL(baseUrl, "phase1");
        try (InputStream stream = phaseOneUrl.openStream()) {
            String body = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            assertTrue("Expected phase1 probe to pass but got: " + body, body.contains("OVERALL=PASS"));
            assertTrue("Missing @Name details: " + body, body.contains("HAS_NAME=true"));
            assertTrue("Missing @In bijection details: " + body, body.contains("HAS_IN_BIJECTION=true"));
            assertTrue("Missing @Observer details: " + body, body.contains("HAS_OBSERVER=true"));
            assertTrue("Missing interceptor details: " + body, body.contains("HAS_BIJECTION_INTERCEPTOR_CLASS=true"));
        }
    }

    @Test
    @RunAsClient
    public void shouldVerifyPageFlowWithCypress() throws Exception {
        String moduleBaseDir = System.getProperty("it.module.basedir");
        assertTrue("Missing system property it.module.basedir", moduleBaseDir != null && !moduleBaseDir.isEmpty());

        File cwd = new File(moduleBaseDir);
        assertTrue("Module base directory does not exist: " + cwd, cwd.exists());

        List<String> command = new ArrayList<String>();
        command.add("cmd.exe");
        command.add("/c");
        command.add("npx");
        command.add("cypress");
        command.add("run");
        command.add("--headless");
        command.add("--browser");
        command.add("electron");
        command.add("--spec");
        command.add("cypress/e2e/jandex-probe.cy.js,cypress/e2e/jandex-negative.cy.js,cypress/e2e/seam-phase1.cy.js,cypress/e2e/seam-phase2.cy.js,cypress/e2e/seam-phase3.cy.js,cypress/e2e/seam-phase4.cy.js,cypress/e2e/jsf-pages.cy.js");
        command.add("--config");
        command.add("baseUrl=" + baseUrl.toString());

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(cwd);
        processBuilder.inheritIO();
        Process process = processBuilder.start();
        int exitCode = process.waitFor();
        assertEquals("Cypress flow test failed", 0, exitCode);
    }
}
