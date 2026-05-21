package org.jboss.seam.example.booking.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.jboss.jandex.Index;
import org.jboss.jandex.Indexer;
import org.jboss.jandex.IndexWriter;
import org.jboss.seam.deployment.AbstractScanner;
import org.jboss.seam.example.booking.Booking;
import org.jboss.seam.example.booking.BookingList;
import org.jboss.seam.example.booking.Hotel;
import org.jboss.seam.example.booking.HotelBooking;
import org.jboss.seam.example.booking.HotelSearching;
import org.jboss.seam.example.booking.User;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.ByteArrayAsset;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;

/**
 * Builds the Seam booking demonstration WAR for WildFly 36 Arquillian tests.
 */
public final class BookingWildFly36Deployment {

    private static final Path BOOKING_WEBAPP = Path.of("..", "booking-web", "src", "main", "webapp");

    private BookingWildFly36Deployment() {
    }

    public static WebArchive create() throws Exception {
        WebArchive archive = ShrinkWrap.create(WebArchive.class, "seam-booking-wf36.war")
                .addClasses(
                        User.class,
                        Hotel.class,
                        Booking.class,
                        HotelSearching.class,
                        HotelBooking.class,
                        BookingList.class,
                        SimpleAuthenticator.class,
                        SimpleChangePassword.class,
                        BookingSessionComponentProbe.class,
                        BookingSeamSessionProbeServlet.class,
                        BookingLoginProbeServlet.class)
                .addAsLibraries(Maven.resolver()
                        .loadPomFromFile("pom.xml")
                        .resolve(
                                "org.jboss.seam:jboss-seam-jakarta:2.3.1.jakarta.bravura.1-SNAPSHOT",
                                "org.jboss.seam:jboss-seam-ui-jakarta:2.3.1.jakarta.bravura.1-SNAPSHOT",
                                "org.javassist:javassist:3.29.2-GA",
                                "io.smallrye:jandex:3.2.7",
                                "org.apache.cxf:cxf-core:3.5.5",
                                "org.dom4j:dom4j:2.1.3",
                                "org.jboss.el:jboss-el:1.0_02.jakarta.bravura.2")
                        .withTransitivity()
                        .asFile())
                .addAsResource("META-INF/persistence.xml")
                .addAsResource("import.sql")
                .addAsResource("seam.properties")
                .addAsResource("META-INF/services/jakarta.faces.application.ApplicationFactory")
                .addAsResource(new ByteArrayAsset(createJandexIndex()), "META-INF/jandex.idx")
                .addAsWebInfResource("WEB-INF/components.xml", "components.xml")
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml")
                .addAsWebInfResource("WEB-INF/faces-config.xml", "faces-config.xml")
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml");

        addWebappResources(archive);
        return archive;
    }

    private static void addWebappResources(WebArchive archive) throws IOException {
        Path webapp = BOOKING_WEBAPP.toAbsolutePath().normalize();
        Files.walk(webapp)
                .filter(Files::isRegularFile)
                .forEach(path -> {
                    String relative = webapp.relativize(path).toString().replace('\\', '/');
                    if (relative.equals("WEB-INF/web.xml")
                            || relative.equals("WEB-INF/components.xml")
                            || relative.equals("WEB-INF/faces-config.xml")) {
                        return;
                    }
                    if (relative.startsWith("WEB-INF/")) {
                        archive.addAsWebInfResource(path.toFile(), relative.substring("WEB-INF/".length()));
                    } else {
                        archive.addAsWebResource(path.toFile(), relative);
                    }
                });
    }

    private static byte[] createJandexIndex() throws IOException {
        Indexer indexer = new Indexer();
        indexClass(indexer, User.class);
        indexClass(indexer, Hotel.class);
        indexClass(indexer, Booking.class);
        indexClass(indexer, HotelSearching.class);
        indexClass(indexer, HotelBooking.class);
        indexClass(indexer, BookingList.class);
        indexClass(indexer, SimpleAuthenticator.class);
        indexClass(indexer, SimpleChangePassword.class);
        indexClass(indexer, BookingSessionComponentProbe.class);
        indexClass(indexer, BookingSeamSessionProbeServlet.class);
        indexClass(indexer, BookingLoginProbeServlet.class);
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
