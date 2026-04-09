package org.jboss.seam.deployment;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.util.Set;
import java.util.Map.Entry;

import org.jboss.jandex.DotName;
import org.jboss.jandex.Index;
import org.jboss.jandex.Indexer;

import jakarta.servlet.ServletContext;

import org.jboss.seam.contexts.ServletLifecycle;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;

/**
 * Abstract base class for {@link Scanner} providing common functionality
 * 
 * This class provides file-system orientated scanning
 * 
 * @author Pete Muir
 *
 */
public abstract class AbstractScanner implements Scanner
{
   
   protected ServletContext servletContext;
   
   private static class Handler
   {
      
      // Cache descriptors for performance
      private Index classIndex;
      private ClassDescriptor classDescriptor;
      private FileDescriptor fileDescriptor;
      
      private Set<Entry<String, DeploymentHandler>> deploymentHandlers;
      private ClassLoader classLoader;
      private String name;
      private ServletContext servletContext;
      
      public Handler(String name, Set<Entry<String, DeploymentHandler>> deploymentHandlers, ClassLoader classLoader,ServletContext servletContext)
      {
         this.deploymentHandlers = deploymentHandlers;
         this.name = name;
         this.classLoader = classLoader;
         this.servletContext=servletContext;
      }
      
      /**
       * Return true if the file was handled (false if it was ignored)
       */
      protected boolean handle(DeploymentHandler deploymentHandler)
      {
         boolean handled = false;
         if (deploymentHandler instanceof ClassDeploymentHandler) 
         {
            if (name.endsWith(".class"))
            {
               ClassDeploymentHandler classDeploymentHandler = (ClassDeploymentHandler) deploymentHandler;
               if (hasAnnotations(getClassIndex(), classDeploymentHandler.getMetadata().getClassAnnotatedWith()))
               {
                  if (getClassDescriptor().getClazz() != null)
                  {
                     log.trace("adding class to deployable list " + name + " for deployment handler " + deploymentHandler.getName());
                     classDeploymentHandler.getClasses().add(getClassDescriptor());
                     handled = true;
                  }
                  else
                  {
                     log.debug("skipping class " + name + " because it cannot be loaded (may reference a type which is not available on the classpath)");
                  }
               }
            }
         }
         else
         {
            if (name.endsWith(deploymentHandler.getMetadata().getFileNameSuffix()))
            {
               deploymentHandler.getResources().add(getFileDescriptor());
               handled = true;
            }
         }
         return handled;
      }
      
      protected boolean handle()
      {
         log.trace("found " + name);
         boolean handled = false;
         for (Entry<String, DeploymentHandler> entry: deploymentHandlers)
         {
            if (handle(entry.getValue()))
            {
               handled = true;
            }
         }
         return handled;
      }
      
      private Index getClassIndex()
      {
         if (classIndex == null)
         {
            try
            {
               classIndex = loadClassIndex(name, classLoader);
            } 
            catch (IOException e)
            {
               throw new RuntimeException("Error loading class file " + name, e);
            }
         }
         return classIndex;
      }
      
      private ClassDescriptor getClassDescriptor()
      {
         if (classDescriptor == null)
         {
            classDescriptor = new ClassDescriptor(name, classLoader,servletContext);
         }
         return classDescriptor;
      }
      
      private FileDescriptor getFileDescriptor()
      {
         if (fileDescriptor == null)
         {
            fileDescriptor = new FileDescriptor(name, classLoader,servletContext);
         }
         return fileDescriptor;
      }
   }
   
   private static final LogProvider log = Logging.getLogProvider(Scanner.class);
   
   private DeploymentStrategy deploymentStrategy;
   
   public AbstractScanner(DeploymentStrategy deploymentStrategy)
   {
      this.deploymentStrategy = deploymentStrategy;
      this.servletContext=deploymentStrategy.getServletContext();
      Indexer.class.getPackage(); // force-load Jandex and fail fast if missing
   }
   @Deprecated
   protected AbstractScanner()
   {
      this.servletContext=ServletLifecycle.getCurrentServletContext();
   }
   
   protected AbstractScanner(ServletContext servletContext)
   {
      this.servletContext=servletContext;
   }
   
   protected static boolean hasAnnotations(Index classIndex, Set<Class<? extends Annotation>> annotationTypes)
   {
      if (annotationTypes.size() > 0)
      {
         for (Class<? extends Annotation> annotationType : annotationTypes)
         {
            DotName annotationName = DotName.createSimple(annotationType.getName());
            if (!classIndex.getAnnotations(annotationName).isEmpty())
            {
               return true;
            }
         }
      }
      return false;
   }
   
   /**
    * Build a Jandex {@link Index} for a given class resource name.
    */
   protected static Index loadClassIndex(String name, ClassLoader classLoader) throws IOException 
   {
      if (name == null)
      {
         throw new NullPointerException("name cannot be null");
      }
      InputStream stream = classLoader.getResourceAsStream(name);
      if (stream == null)
      {
         throw new IllegalStateException("Cannot load " + name + " from " + classLoader + " (using getResourceAsStream() returned null)");
      }

      try 
      { 
         Indexer indexer = new Indexer();
         indexer.index(stream);
         return indexer.complete();
      } 
      finally 
      { 
         stream.close(); 
      }
   }
   
   public DeploymentStrategy getDeploymentStrategy()
   {
      return deploymentStrategy;
   }
   
   public long getTimestamp()
   {
      return Long.MAX_VALUE;
   }
   
   protected void handleItem(String name)
   {
      handle(name);
   }
   
   
   protected boolean handle(String name)
   {
      return new Handler(name, deploymentStrategy.getDeploymentHandlers().entrySet(), deploymentStrategy.getClassLoader(),servletContext).handle();
   }
   
   public void scanDirectories(File[] directories, File[] excludedDirectories)
   {
      scanDirectories(directories);
   }

}
