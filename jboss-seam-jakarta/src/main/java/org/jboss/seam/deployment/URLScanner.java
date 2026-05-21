package org.jboss.seam.deployment;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.DotName;
import org.jboss.jandex.Index;
import org.jboss.jandex.IndexReader;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;

/**
 * Jakarta-only URLScanner implementation.
 *
 * This scanner is intentionally Jandex-only:
 * - no directory/file-system scanning
 * - no archive walking fallback
 */
public class URLScanner extends AbstractScanner
{
   private static final LogProvider log = Logging.getLogProvider(URLScanner.class);

   public URLScanner(DeploymentStrategy deploymentStrategy)
   {
      super(deploymentStrategy);
   }

   public void scanDirectories(File[] directories)
   {
      scanDirectories(directories, new File[0]);
   }

   @Override
   public void scanDirectories(File[] directories, File[] excludedDirectories)
   {
      log.debug("Skipping file-system directory scanning in Jakarta mode (Jandex-only)");
   }

   public void scanResources(String[] resources)
   {
      scanResourcesWithJandex(resources);
   }

   private void scanResourcesWithJandex(String[] resources)
   {
      Map<String, ArchiveResourceRef> seamArchives = new HashMap<String, ArchiveResourceRef>();
      for (String resourceName : resources)
      {
         collectSeamArchiveMarkers(resourceName, seamArchives);
      }

      for (ArchiveResourceRef archiveRef : seamArchives.values())
      {
         Index index = loadJandexIndexOrThrow(archiveRef);
         addIndexedDeploymentDescriptors(index);
         addKnownResourceDescriptor("META-INF/components.xml");
      }
   }

   private void collectSeamArchiveMarkers(String resourceName, Map<String, ArchiveResourceRef> seamArchives)
   {
      try
      {
         Enumeration<URL> urlEnum = getDeploymentStrategy().getClassLoader().getResources(resourceName);
         while (urlEnum.hasMoreElements())
         {
            URL url = urlEnum.nextElement();
            String archiveKey = archiveKey(url, resourceName);
            if (!seamArchives.containsKey(archiveKey))
            {
               seamArchives.put(archiveKey, new ArchiveResourceRef(url, resourceName));
            }
            addKnownResourceDescriptor(resourceName);
         }
      }
      catch (IOException ioe)
      {
         log.warn("could not read: " + resourceName, ioe);
      }
   }

   private void addKnownResourceDescriptor(String resourceName)
   {
      for (Entry<String, DeploymentHandler> entry : getDeploymentStrategy().getDeploymentHandlers().entrySet())
      {
         DeploymentHandler handler = entry.getValue();
         String suffix = handler.getMetadata().getFileNameSuffix();
         if (suffix != null && resourceName.endsWith(suffix))
         {
            handler.getResources().add(new FileDescriptor(resourceName, getDeploymentStrategy().getClassLoader(), getDeploymentStrategy().getServletContext()));
         }
      }
   }

   private void addIndexedDeploymentDescriptors(Index index)
   {
      ClassLoader classLoader = getDeploymentStrategy().getClassLoader();
      for (Entry<String, DeploymentHandler> entry : getDeploymentStrategy().getDeploymentHandlers().entrySet())
      {
         DeploymentHandler handler = entry.getValue();
         if (handler instanceof ClassDeploymentHandler)
         {
            ClassDeploymentHandler classHandler = (ClassDeploymentHandler) handler;
            addIndexedClassDescriptors(index, classHandler, classLoader);
         }
         else if ("/package-info.class".equals(handler.getMetadata().getFileNameSuffix()))
         {
            addIndexedPackageDescriptors(index, handler, classLoader);
         }
      }
   }

   private void addIndexedClassDescriptors(Index index, ClassDeploymentHandler classHandler, ClassLoader classLoader)
   {
      Set<Class<? extends java.lang.annotation.Annotation>> annotations = classHandler.getMetadata().getClassAnnotatedWith();
      for (Class<? extends java.lang.annotation.Annotation> annotation : annotations)
      {
         DotName annotationName = DotName.createSimple(annotation.getName());
         for (AnnotationInstance instance : index.getAnnotations(annotationName))
         {
            if (instance.target().kind() == org.jboss.jandex.AnnotationTarget.Kind.CLASS)
            {
               String classResource = instance.target().asClass().name().toString().replace('.', '/') + ".class";
               ClassDescriptor descriptor = new ClassDescriptor(classResource, classLoader, getDeploymentStrategy().getServletContext());
               if (descriptor.isLoaded())
               {
                  classHandler.getClasses().add(descriptor);
               }
               else
               {
                  log.debug("Skipping jandex-indexed class that is not loadable: " + classResource);
               }
            }
         }
      }
   }

   private void addIndexedPackageDescriptors(Index index, DeploymentHandler handler, ClassLoader classLoader)
   {
      DotName namespaceAnnotation = DotName.createSimple("org.jboss.seam.annotations.Namespace");
      for (AnnotationInstance instance : index.getAnnotations(namespaceAnnotation))
      {
         if (instance.target().kind() == org.jboss.jandex.AnnotationTarget.Kind.CLASS)
         {
            String classResource = instance.target().asClass().name().toString().replace('.', '/') + ".class";
            if (classResource.endsWith("/package-info.class"))
            {
               handler.getResources().add(new FileDescriptor(classResource, classLoader, getDeploymentStrategy().getServletContext()));
            }
         }
      }
   }

   private Index loadJandexIndexOrThrow(ArchiveResourceRef archiveRef)
   {
      try
      {
         URL indexUrl = jandexUrlForArchiveResource(archiveRef.url, archiveRef.resourceName);
         InputStream stream = indexUrl.openStream();
         try
         {
            return new IndexReader(stream).read();
         }
         finally
         {
            stream.close();
         }
      }
      catch (IOException e)
      {
         throw new IllegalStateException("Jakarta Seam requires META-INF/jandex.idx for Seam archive marker "
               + archiveRef.resourceName + " at " + archiveRef.url, e);
      }
   }

   private URL jandexUrlForArchiveResource(URL markerUrl, String markerResourceName) throws IOException
   {
      String external = markerUrl.toExternalForm();
      int bangIndex = external.indexOf('!');
      if (bangIndex > 0)
      {
         return new URL(external.substring(0, bangIndex) + "!/META-INF/jandex.idx");
      }

      String markerSuffix = markerResourceName;
      int markerIndex = external.lastIndexOf(markerSuffix);
      if (markerIndex >= 0)
      {
         return new URL(external.substring(0, markerIndex) + "META-INF/jandex.idx");
      }
      return new URL(external + (external.endsWith("/") ? "" : "/") + "META-INF/jandex.idx");
   }

   private String archiveKey(URL markerUrl, String markerResourceName)
   {
      String external = markerUrl.toExternalForm();
      int bangIndex = external.indexOf('!');
      if (bangIndex > 0)
      {
         return external.substring(0, bangIndex);
      }

      String markerSuffix = markerResourceName;
      int markerIndex = external.lastIndexOf(markerSuffix);
      if (markerIndex >= 0)
      {
         return external.substring(0, markerIndex);
      }
      return external;
   }

   private static final class ArchiveResourceRef
   {
      private final URL url;
      private final String resourceName;

      private ArchiveResourceRef(URL url, String resourceName)
      {
         this.url = url;
         this.resourceName = resourceName;
      }
   }
}
