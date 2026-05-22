package org.jboss.seam.test.integration;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.apache.cxf.common.security.GroupPrincipal;
import org.dom4j.DocumentException;
import org.jboss.el.util.ReflectionUtil;
import org.jboss.jandex.Index;
import org.jboss.jandex.Indexer;
import org.jboss.jandex.IndexWriter;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.deployment.AbstractScanner;
import org.jboss.seam.mock.MockSeamListener;
import org.jboss.seam.ui.resource.WebResource;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.ByteArrayAsset;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;

import javassist.util.proxy.MethodFilter;

/**
 * Builds Seam integration test WARs for WildFly 36 using Jakarta Seam artifacts.
 */
public final class Deployments {

    private Deployments() {
    }

    public static WebArchive defaultSeamDeployment() {
        return defaultSeamDeployment("WEB-INF/components-mock.xml");
    }

    public static WebArchive defaultSeamDeployment(Class<?> testClass, Class<?>... indexClasses) {
        return defaultSeamDeployment("WEB-INF/components-mock.xml", archiveName(testClass), testClass, indexClasses);
    }

    private static String archiveName(Class<?> testClass) {
        if (testClass == null) {
            return "seam-integration-tests.war";
        }
        return "seam-it-" + testClass.getSimpleName().toLowerCase() + ".war";
    }

    public static WebArchive realSeamDeployment() {
        return realSeamDeployment((Class<?>) null);
    }

    public static WebArchive realSeamDeployment(Class<?> testClass, Class<?>... indexClasses) {
        WebArchive war = baseArchive(true, false, archiveName(testClass))
                .addAsWebInfResource("WEB-INF/components.xml", "components.xml")
                .addAsWebInfResource("WEB-INF/pages.xml", "pages.xml")
                .addAsWebInfResource("WEB-INF/real-web.xml", "web.xml")
                .addAsWebInfResource("WEB-INF/faces-config.xml", "faces-config.xml");
        if (indexClasses.length > 0) {
            war.addClasses(indexClasses);
        }
        return addJandexIndex(war, indexClasses(testClass, indexClasses));
    }

    public static WebArchive jbpmSeamDeployment(Class<?>... indexClasses) {
        WebArchive war = baseArchive(true, true, "seam-integration-jbpm.war")
                .addAsResource("testProcess1.jpdl.xml")
                .addAsResource("testProcess2.jpdl.xml")
                .addAsResource("testProcess3.jpdl.xml")
                .addAsResource("testProcess4.jpdl.xml")
                .addAsResource("jbpm.cfg.xml")
                .addAsResource("hibernate.cfg.xml")
                .addAsWebInfResource("WEB-INF/components-jbpm.xml", "components.xml")
                .addAsWebInfResource("WEB-INF/pages.xml", "pages.xml")
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml");
        if (indexClasses.length > 0) {
            war.addClasses(indexClasses);
        }
        return addJandexIndex(war, indexClasses(null, indexClasses));
    }

    public static WebArchive defaultSeamDeployment(String customComponentsXml) {
        return defaultSeamDeployment(customComponentsXml, "seam-integration-tests.war", null);
    }

    public static WebArchive defaultSeamDeployment(String customComponentsXml, Class<?> testClass, Class<?>... indexClasses) {
        return defaultSeamDeployment(customComponentsXml, archiveName(testClass), testClass, indexClasses);
    }

    private static WebArchive defaultSeamDeployment(String customComponentsXml, String archiveName, Class<?> testClass, Class<?>... indexClasses) {
        WebArchive war = baseArchive(false, false, archiveName)
                .addAsWebInfResource(customComponentsXml, "components.xml")
                .addAsWebInfResource("WEB-INF/pages.xml", "pages.xml")
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml");
        if (indexClasses.length > 0) {
            war.addClasses(indexClasses);
        }
        return addJandexIndex(war, indexClasses(testClass, indexClasses));
    }

    public static WebArchive withJandex(WebArchive war, Class<?> testClass, Class<?>... additionalClasses) {
        return addJandexIndex(war, indexClasses(testClass, additionalClasses));
    }

    private static Class<?>[] indexClasses(Class<?> testClass, Class<?>... additionalClasses) {
        List<Class<?>> classes = new ArrayList<>();
        classes.add(AbstractScanner.class);
        if (testClass != null) {
            collectNamedComponents(testClass, classes);
        }
        for (Class<?> clazz : additionalClasses) {
            if (clazz.isAnnotationPresent(Name.class) && !classes.contains(clazz)) {
                classes.add(clazz);
            }
            collectNamedComponents(clazz, classes);
        }
        return classes.toArray(Class<?>[]::new);
    }

    private static void collectNamedComponents(Class<?> type, List<Class<?>> classes) {
        if (type.isAnnotationPresent(Name.class) && !classes.contains(type)) {
            classes.add(type);
        }
        for (Class<?> inner : type.getDeclaredClasses()) {
            collectNamedComponents(inner, classes);
        }
    }

    private static WebArchive addJandexIndex(WebArchive war, Class<?>... classes) {
        try {
            return war.addAsResource(new ByteArrayAsset(createJandexIndex(Arrays.asList(classes))), "META-INF/jandex.idx");
        } catch (IOException e) {
            throw new IllegalStateException("Failed to build jandex index", e);
        }
    }

    private static WebArchive baseArchive(boolean includeSeamUi, boolean includeJbpm, String archiveName) {
        WebArchive war = ShrinkWrap.create(WebArchive.class, archiveName)
                .addAsLibraries(
                        seamJakartaJar(),
                        jarFor(MethodFilter.class),
                        jarFor(Indexer.class),
                        jarFor(GroupPrincipal.class),
                        jarFor(DocumentException.class),
                        jarFor(ReflectionUtil.class),
                        jarFor(jakarta.faces.webapp.FacesServlet.class))
                .addAsResource("seam.properties")
                .addAsResource("components.properties")
                .addAsResource("messages_en.properties")
                .addAsResource("META-INF/persistence.xml")
                .addAsWebResource("index.xhtml")
                .addAsWebResource("page.xhtml")
                .addAsWebResource("test.xhtml")
                .addAsWebResource("pageWithDescription.xhtml")
                .addAsWebResource("pageWithoutDescription.xhtml")
                .addAsWebResource("pageWithAnotherDescription.xhtml")
                .addAsWebResource("pageWithParameter.xhtml")
                .addAsWebResource("pageWithRequiredParameter.xhtml")
                .addAsWebResource("pageWithValidateModelDisabledParameter.xhtml")
                .addAsWebInfResource("WEB-INF/jboss-deployment-structure.xml", "jboss-deployment-structure.xml")
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml");

        if (includeSeamUi) {
            war.addAsLibraries(seamUiJakartaJar());
        }

        if (includeJbpm) {
            war.addAsLibraries(Maven.resolver()
                    .loadPomFromFile("pom.xml")
                    .resolve("org.jbpm.jbpm3:jbpm-jpdl")
                    .withTransitivity()
                    .asFile());
        }

        return war;
    }

    private static File seamJakartaJar() {
        return asLibraryJar(jarFor(MockSeamListener.class), "jboss-seam-jakarta.jar");
    }

    private static File seamUiJakartaJar() {
        return asLibraryJar(jarFor(WebResource.class), "jboss-seam-ui-jakarta.jar");
    }

    private static File asLibraryJar(File location, String jarName) {
        if (location.isFile()) {
            return location;
        }
        try {
            File jarFile = File.createTempFile(jarName.replace(".jar", "-"), ".jar");
            jarFile.deleteOnExit();
            int prefixLength = location.getAbsolutePath().length() + 1;
            try (JarOutputStream out = new JarOutputStream(new FileOutputStream(jarFile))) {
                addDirectoryToJar(out, location, prefixLength);
            }
            return jarFile;
        } catch (IOException e) {
            throw new IllegalStateException("Cannot package " + location + " for deployment", e);
        }
    }

    private static void addDirectoryToJar(JarOutputStream out, File source, int prefixLength) throws IOException {
        File[] files = source.listFiles();
        if (files == null) {
            return;
        }
        for (File file : files) {
            if (file.isDirectory()) {
                addDirectoryToJar(out, file, prefixLength);
            } else {
                String entryName = file.getAbsolutePath().substring(prefixLength).replace('\\', '/');
                out.putNextEntry(new JarEntry(entryName));
                try (InputStream in = new FileInputStream(file)) {
                    in.transferTo(out);
                }
                out.closeEntry();
            }
        }
    }

    private static File jarFor(Class<?> anchor) {
        try {
            return new File(anchor.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (Exception e) {
            throw new IllegalStateException("Cannot locate JAR for " + anchor.getName(), e);
        }
    }

    private static byte[] createJandexIndex(List<Class<?>> classes) throws IOException {
        Indexer indexer = new Indexer();
        for (Class<?> clazz : classes) {
            indexClass(indexer, clazz);
        }
        Index index = indexer.complete();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        new IndexWriter(output).write(index);
        return output.toByteArray();
    }

    private static void indexClass(Indexer indexer, Class<?> clazz) throws IOException {
        String resourceName = clazz.getName().replace('.', '/') + ".class";
        try (InputStream stream = clazz.getClassLoader().getResourceAsStream(resourceName)) {
            if (stream == null) {
                throw new IllegalStateException("Missing class resource: " + resourceName);
            }
            indexer.index(stream);
        }
    }
}
