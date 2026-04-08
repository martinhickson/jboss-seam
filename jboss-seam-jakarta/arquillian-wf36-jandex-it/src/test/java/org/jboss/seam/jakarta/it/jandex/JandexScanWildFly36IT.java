package org.jboss.seam.deployment;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javassist.util.proxy.MethodFilter;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.jandex.Indexer;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.seam.deployment.JandexScanSupport;
import org.jboss.seam.jakarta.it.jandex.ScannedSeamComponent;
import org.jboss.seam.jakarta.it.jandex.JsfPageOneBean;
import org.jboss.seam.jakarta.it.jandex.JsfPageTwoBean;
import org.jboss.shrinkwrap.api.ShrinkWrap;
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
        return ShrinkWrap.create(WebArchive.class, "jandex-scan-example.war")
                .addClasses(
                        ScannedSeamComponent.class,
                        JsfPageOneBean.class,
                        JsfPageTwoBean.class,
                        JandexScanSupport.class,
                        ScannerProbeServlet.class,
                        PageFlowServlet.class)
                .addAsLibraries(seamLibrary, jandexLibrary, javassistLibrary)
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml")
                .addAsWebResource("pages/page1.xhtml", "pages/page1.xhtml")
                .addAsWebResource("pages/page2.xhtml", "pages/page2.xhtml")
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml")
                .addAsResource("META-INF/seam.properties", "META-INF/seam.properties");
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
        command.add("cypress/e2e/jandex-probe.cy.js,cypress/e2e/jsf-pages.cy.js");
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
