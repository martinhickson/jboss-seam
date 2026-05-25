package org.jboss.seam.example.booking.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.jboss.jandex.Index;
import org.jboss.jandex.Indexer;
import org.jboss.jandex.IndexWriter;
import org.jboss.seam.deployment.AbstractScanner;
import org.jboss.seam.example.booking.Authenticator;
import org.jboss.seam.example.booking.AuthenticatorAction;
import org.jboss.seam.example.booking.Booking;
import org.jboss.seam.example.booking.BookingList;
import org.jboss.seam.example.booking.BookingListAction;
import org.jboss.seam.example.booking.Hotel;
import org.jboss.seam.example.booking.HotelBooking;
import org.jboss.seam.example.booking.HotelBookingAction;
import org.jboss.seam.example.booking.HotelSearching;
import org.jboss.seam.example.booking.HotelSearchingAction;
import org.jboss.seam.example.booking.User;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.ByteArrayAsset;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.importer.ZipImporter;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;

import java.io.File;

/**
 * Builds the Seam booking EAR (EJB + WAR) for WildFly 36 Arquillian tests.
 */
public final class BookingEarWildFly36Deployment {

    private static final Path BOOKING_WEBAPP = Path.of("..", "booking-web", "src", "main", "webapp");

    private BookingEarWildFly36Deployment() {
    }

    public static EnterpriseArchive create(Class<?>... testClasses) throws Exception {
        return create("seam-booking-ejb.ear", testClasses);
    }

    public static EnterpriseArchive create(String earName, Class<?>... testClasses) throws Exception {
        JavaArchive ejbJar = createEjbModule();
        WebArchive webWar = createWebModule(testClasses);
        EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, earName)
                .addAsModule(createJbossSeamEjbModule())
                .addAsModule(ejbJar)
                .addAsModule(webWar)
                .addAsApplicationResource("META-INF/application.xml", "application.xml")
                .addAsApplicationResource("META-INF/jboss-deployment-structure.xml", "jboss-deployment-structure.xml")
                .addAsLibraries(Maven.resolver()
                        .loadPomFromFile("pom.xml")
                        .resolve(
                                "org.jboss.seam:jboss-seam-ui-jakarta:2.3.1.jakarta.bravura.1-SNAPSHOT",
                                "org.javassist:javassist:3.29.2-GA",
                                "io.smallrye:jandex:3.2.7",
                                "org.apache.cxf:cxf-core:3.5.5",
                                "org.dom4j:dom4j:2.1.3",
                                "org.jboss.el:jboss-el:1.0_02.jakarta.bravura.2",
                                "org.jbpm.jbpm3:jbpm-jpdl:3.2.10.SP3_seam2")
                        .withTransitivity()
                        .asFile())
                .addAsLibraries(createJbossElMessagesJar());
        return ear;
    }

    private static JavaArchive createJbossSeamEjbModule() {
        File seamJar = Maven.resolver()
                .loadPomFromFile("pom.xml")
                .resolve("org.jboss.seam:jboss-seam-jakarta:2.3.1.jakarta.bravura.1-SNAPSHOT")
                .withoutTransitivity()
                .asSingleFile();
        JavaArchive archive = ShrinkWrap.create(ZipImporter.class, "jboss-seam.jar")
                .importFrom(seamJar)
                .as(JavaArchive.class);
        archive.delete("META-INF/components.xml");
        return archive;
    }

    private static JavaArchive createEjbModule() throws IOException {
        return ShrinkWrap.create(JavaArchive.class, "booking-ejb.jar")
                .addClasses(
                        User.class,
                        Hotel.class,
                        Booking.class,
                        HotelBooking.class,
                        HotelBookingAction.class,
                        BookingList.class,
                        BookingListAction.class,
                        HotelSearching.class,
                        HotelSearchingAction.class,
                        Authenticator.class,
                        AuthenticatorAction.class)
                .addAsResource("META-INF/persistence.xml")
                .addAsResource("META-INF/ejb-jar.xml")
                .addAsResource("import.sql")
                .addAsResource("ejb-seam.properties", "seam.properties")
                .addAsResource(EmptyAsset.INSTANCE, "META-INF/beans.xml")
                .addAsResource(new ByteArrayAsset(createEjbJandexIndex()), "META-INF/jandex.idx");
    }

    private static WebArchive createWebModule(Class<?>... testClasses) throws Exception {
        WebArchive archive = ShrinkWrap.create(WebArchive.class, "booking-web.war")
                .addClasses(
                        MapCacheProvider.class,
                        BookingSeamSessionProbeServlet.class,
                        BookingLoginProbeServlet.class,
                        BookingSessionComponentProbe.class);
        if (testClasses.length > 0) {
            archive.addClasses(testClasses);
        }
        archive.addAsResource("seam.properties")
                .addAsResource("META-INF/services/jakarta.faces.application.ApplicationFactory")
                .addAsResource(new ByteArrayAsset(createWebJandexIndex()), "META-INF/jandex.idx")
                .addAsWebInfResource("WEB-INF/components.xml", "components.xml")
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml")
                .addAsWebInfResource("WEB-INF/faces-config.xml", "faces-config.xml")
                .addAsWebInfResource("WEB-INF/jboss-web.xml", "jboss-web.xml")
                .addAsWebInfResource("WEB-INF/jboss-deployment-structure.xml", "jboss-deployment-structure.xml")
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml");
        addWebappResources(archive);
        return archive;
    }

    private static JavaArchive createJbossElMessagesJar() {
        return ShrinkWrap.create(JavaArchive.class, "jboss-el-messages.jar")
                .addAsResource("org/jboss/el/Messages.properties");
    }

    private static void addWebappResources(WebArchive archive) throws IOException {
        Path webapp = BOOKING_WEBAPP.toAbsolutePath().normalize();
        Files.walk(webapp)
                .filter(Files::isRegularFile)
                .forEach(path -> {
                    String relative = webapp.relativize(path).toString().replace('\\', '/');
                    if (relative.equals("WEB-INF/web.xml")
                            || relative.equals("WEB-INF/components.xml")
                            || relative.equals("WEB-INF/faces-config.xml")
                            || relative.equals("WEB-INF/jboss-web.xml")
                            || relative.equals("WEB-INF/jboss-deployment-structure.xml")) {
                        return;
                    }
                    if (relative.startsWith("WEB-INF/")) {
                        archive.addAsWebInfResource(path.toFile(), relative.substring("WEB-INF/".length()));
                    } else {
                        archive.addAsWebResource(path.toFile(), relative);
                    }
                });
    }

    private static byte[] createEjbJandexIndex() throws IOException {
        Indexer indexer = new Indexer();
        indexClass(indexer, User.class);
        indexClass(indexer, Hotel.class);
        indexClass(indexer, Booking.class);
        indexClass(indexer, HotelBookingAction.class);
        indexClass(indexer, BookingListAction.class);
        indexClass(indexer, HotelSearchingAction.class);
        indexClass(indexer, AuthenticatorAction.class);
        Index index = indexer.complete();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        new IndexWriter(output).write(index);
        return output.toByteArray();
    }

    private static byte[] createWebJandexIndex() throws IOException {
        Indexer indexer = new Indexer();
        indexClass(indexer, MapCacheProvider.class);
        indexClass(indexer, AbstractScanner.class);
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
