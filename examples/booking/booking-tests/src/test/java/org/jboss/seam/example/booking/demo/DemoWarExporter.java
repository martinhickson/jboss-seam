package org.jboss.seam.example.booking.demo;

import java.nio.file.Files;
import java.nio.file.Path;

import org.jboss.seam.example.booking.test.BookingWildFly36Deployment;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.jboss.shrinkwrap.api.spec.WebArchive;

/**
 * Exports the WildFly 36 booking demo WAR for local deployment.
 */
public final class DemoWarExporter
{
   public static void main(String[] args) throws Exception
   {
      Path output = Path.of("target", "seam-booking-demo.war");
      WebArchive war = BookingWildFly36Deployment.create();
      Files.createDirectories(output.getParent());
      war.as(ZipExporter.class).exportTo(output.toFile(), true);
      System.out.println("Exported " + output.toAbsolutePath());
   }

   private DemoWarExporter()
   {
   }
}
