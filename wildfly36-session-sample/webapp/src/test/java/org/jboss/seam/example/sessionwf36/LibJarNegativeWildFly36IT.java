package org.jboss.seam.example.sessionwf36;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.apache.cxf.common.security.GroupPrincipal;
import org.dom4j.DocumentException;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.el.util.ReflectionUtil;
import org.jboss.seam.servlet.SeamListener;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;

import javassist.util.proxy.MethodFilter;
import org.jboss.jandex.Indexer;

/**
 * Negative coverage: lib JAR with {@code @Name} but no Seam archive marker is not scanned.
 */
@RunWith(Arquillian.class)
public class LibJarNegativeWildFly36IT {

    @Deployment(testable = false)
    public static WebArchive createDeployment() throws Exception {
        File seamLibrary = new File(SeamListener.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File javassistLibrary = new File(MethodFilter.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File jandexLibrary = new File(Indexer.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File dom4jLibrary = new File(DocumentException.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File cxfCoreLibrary = new File(GroupPrincipal.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        File jbossElLibrary = new File(ReflectionUtil.class.getProtectionDomain().getCodeSource().getLocation().toURI());

        JavaArchive libWithoutMarker = ShrinkWrap.create(JavaArchive.class, "enhanced-without-marker.jar")
                .addClass(org.jboss.seam.example.sessionwf36.lib.EnhancedSeamSession.class)
                .addAsResource(new File("../enhanced-seam-lib/target/classes/META-INF/jandex.idx"));

        File webInf = new File("src/main/webapp/WEB-INF");

        return ShrinkWrap.create(WebArchive.class, "seam-lib-negative-it.war")
                .addClass(LibJarProbeServlet.class)
                .addAsLibraries(seamLibrary, javassistLibrary, jandexLibrary, dom4jLibrary, cxfCoreLibrary, jbossElLibrary)
                .addAsLibraries(libWithoutMarker)
                .addAsWebInfResource("WEB-INF/web-lib-negative.xml", "web.xml")
                .addAsWebInfResource(new File(webInf, "beans.xml"), "beans.xml");
    }

    @ArquillianResource
    private URL baseUrl;

    @Test
    @RunAsClient
    public void libJar_withoutSeamProperties_doesNotOverrideBuiltInSession() throws Exception {
        URL url = new URL(baseUrl, "probe/lib/enhanced");
        try (InputStream stream = url.openStream()) {
            String body = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            assertTrue("Expected built-in Session in session map: " + body,
                    body.contains("MAP_VALUE_CLASS=org.jboss.seam.web.Session"));
            assertTrue("Expected built-in Session in HttpSession: " + body,
                    body.contains("HTTPSESSION_VALUE_CLASS=org.jboss.seam.web.Session"));
            assertFalse("Expected built-in Session, not lib override: " + body,
                    body.contains("SOURCE=WEB-INF/lib"));
        }
    }
}
