package org.jboss.seam.deployment;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.DotName;
import org.jboss.jandex.Index;
import org.jboss.jandex.IndexReader;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;

/**
 * Implementation of {@link Scanner} which can scan a {@link URLClassLoader}
 * 
 * @author Thomas Heute
 * @author Gavin King
 * @author Norman Richards
 * @author Pete Muir
 *
 */
public class URLScanner extends AbstractScanner
{
   private static final LogProvider log = Logging.getLogProvider(URLScanner.class);
   
   private long timestamp;
   
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
      if (isJakartaRuntime())
      {
         log.debug("Skipping file-system directory scanning in Jakarta mode (Jandex-only)");
         return;
      }
      for (File directory : directories)
      {
         handleDirectory(directory, null, excludedDirectories);
      }
   }
   
   public void scanResources(String[] resources)
   {
      if (isJakartaRuntime())
      {
         scanResourcesWithJandex(resources);
         return;
      }

      Set<String> paths = new HashSet<String>();
      for (String resourceName : resources)
      {
         try
         {
            Enumeration<URL> urlEnum = getDeploymentStrategy().getClassLoader().getResources(resourceName);
            while ( urlEnum.hasMoreElements() )
            {
               String urlPath = normalizeResourcePath(urlEnum.nextElement(), resourceName);
               paths.add(urlPath);
            }
         }
         catch (IOException ioe) 
         {
            log.warn("could not read: " + resourceName, ioe);
         }
      }
      handle(paths);
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
               classHandler.getClasses().add(new ClassDescriptor(classResource, classLoader, getDeploymentStrategy().getServletContext()));
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

   private boolean isJakartaRuntime()
   {
      try
      {
         ClassLoader scannerClassLoader = URLScanner.class.getClassLoader();
         if (scannerClassLoader != null)
         {
            scannerClassLoader.loadClass("jakarta.servlet.ServletContext");
            return true;
         }
      }
      catch (ClassNotFoundException e)
      {
         // Fall through to constructor-signature check below.
      }
      return isJakartaClassDescriptorSignature();
   }

   private boolean isJakartaClassDescriptorSignature()
   {
      java.lang.reflect.Constructor<?>[] constructors = ClassDescriptor.class.getConstructors();
      for (java.lang.reflect.Constructor<?> constructor : constructors)
      {
         Class<?>[] parameterTypes = constructor.getParameterTypes();
         if (parameterTypes.length == 3 && "java.lang.String".equals(parameterTypes[0].getName()))
         {
            return "jakarta.servlet.ServletContext".equals(parameterTypes[2].getName());
         }
      }
      return false;
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

   private String normalizeResourcePath(URL resourceUrl, String resourceName) throws IOException
   {
      String urlPath = resourceUrl.getFile();
      urlPath = URLDecoder.decode(urlPath, "UTF-8");
      if ( urlPath.startsWith("file:") )
      {
         urlPath = urlPath.substring(5);
      }
      if ( urlPath.indexOf('!')>0 )
      {
         return urlPath.substring(0, urlPath.indexOf('!'));
      }

      // WildFly vfs-style URLs may embed archive paths, e.g. "...foo.war/WEB-INF/classes".
      int archiveIndex = indexOfArchivePath(urlPath, ".jar");
      if (archiveIndex < 0)
      {
         archiveIndex = indexOfArchivePath(urlPath, ".war");
      }
      if (archiveIndex >= 0)
      {
         return urlPath.substring(0, archiveIndex + 4);
      }

      File dirOrArchive = new File(urlPath);
      if ( resourceName!=null && resourceName.lastIndexOf('/')>0 )
      {
         //for META-INF/components.xml
         dirOrArchive = dirOrArchive.getParentFile();
      }
      return dirOrArchive.getParent();
   }

   private int indexOfArchivePath(String path, String extension)
   {
      String lowerPath = path.toLowerCase();
      String lowerExtension = extension.toLowerCase();
      int forwardSlashIndex = lowerPath.indexOf(lowerExtension + "/");
      int backwardSlashIndex = lowerPath.indexOf(lowerExtension + "\\");
      int exactIndex = lowerPath.indexOf(lowerExtension);

      if (forwardSlashIndex >= 0)
      {
         return forwardSlashIndex;
      }
      if (backwardSlashIndex >= 0)
      {
         return backwardSlashIndex;
      }
      if (exactIndex >= 0 && exactIndex + extension.length() == path.length())
      {
         return exactIndex;
      }
      return -1;
   }
   
   protected void handle(Set<String> paths)
   {
      for ( String urlPath: paths )
      {
         try
         {
            log.trace("scanning: " + urlPath);
            File file = new File(urlPath);
            if ( file.isDirectory() )
            {
               handleDirectory(file, null);
            }
            else
            {
               handleArchiveByFile(file);
            }
         }
         catch (IOException ioe) 
         {
            log.warn("could not read entries", ioe);
         }
      }
   }

   private void handleArchiveByFile(File file) throws IOException
   {
      try
      {
         log.trace("archive: " + file);
         touchTimestamp(file);
         ZipFile zip = new ZipFile(file);
         Enumeration<? extends ZipEntry> entries = zip.entries();
         while ( entries.hasMoreElements() )
         {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            handle(name);
         }
      }
      catch (ZipException e)
      {
         throw new RuntimeException("Error handling file " + file, e);
      }
   }

   private void handleDirectory(File file, String path)
   {
      handleDirectory(file, path, new File[0]);
   }
   
   private void handleDirectory(File file, String path, File[] excludedDirectories)
   {
      for (File excludedDirectory : excludedDirectories)
      {
         if (file.equals(excludedDirectory))
         {
            log.trace("skipping excluded directory: " + file);
            return;
         }
      } 
      
      log.trace("handling directory: " + file);
      for ( File child: file.listFiles() )
      {
         String newPath = path==null ? child.getName() : path + '/' + child.getName();
         if ( child.isDirectory() )
         {
            handleDirectory(child, newPath, excludedDirectories);
         }
         else
         {
            if (handle(newPath))
            {
               // only try to update the timestamp on this scanner if the file was actually handled
               touchTimestamp(child);
            }
         }
      }
   }

   private void touchTimestamp(File file)
   {
      if (file.lastModified() > timestamp)
      {
         timestamp = file.lastModified();
      }
   }
   
   @Override
   public long getTimestamp()
   {
      return timestamp;
   }
   
}
