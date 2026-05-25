package org.jboss.seam.ui.handler;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import javax.el.ELException;
import javax.faces.FacesException;
import javax.faces.component.UIComponent;
import javax.faces.view.facelets.ComponentConfig;
import javax.faces.view.facelets.ComponentHandler;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.TagConfig;

/**
 * Decorating handler
 *
 * @author mnovotny
 */
public class DecorateHandler extends ComponentHandler
{
   private static final String MOJARRA_DECORATE_HANDLER =
         "com.sun.faces.facelets.tag.ui.DecorateHandler";

   private Object delegate;
   private final ComponentConfig handlerConfig;

   public DecorateHandler(ComponentConfig config)
   {
      super(config);
      handlerConfig = config;
   }

   @Override
   public void applyNextHandler(FaceletContext context, UIComponent component)
         throws IOException, FacesException, ELException
   {
      if (tag.getAttributes().get("template") != null)
      {
         applyMojarraDelegate(context, component);
      }
      else
      {
         nextHandler.apply(context, component);
      }
   }

   private void applyMojarraDelegate(FaceletContext context, UIComponent component)
         throws IOException, FacesException, ELException
   {
      Object mojarraDelegate = getMojarraDelegate(context);
      try
      {
         Method apply = mojarraDelegate.getClass().getMethod(
               "apply", FaceletContext.class, UIComponent.class);
         apply.invoke(mojarraDelegate, context, component);
      }
      catch (ReflectiveOperationException e)
      {
         Throwable cause = e.getCause();
         if (cause instanceof IOException)
         {
            throw (IOException) cause;
         }
         if (cause instanceof FacesException)
         {
            throw (FacesException) cause;
         }
         if (cause instanceof ELException)
         {
            throw (ELException) cause;
         }
         throw new FacesException("Unable to apply Mojarra DecorateHandler delegate", e);
      }
      catch (RuntimeException e)
      {
         throw e;
      }
   }

   private Object getMojarraDelegate(FaceletContext context)
   {
      if (delegate == null)
      {
         try
         {
            Class<?> clazz = Class.forName(
                  MOJARRA_DECORATE_HANDLER, true, resolveFacesImplClassLoader(context));
            Constructor<?> ctor = clazz.getConstructor(TagConfig.class);
            delegate = ctor.newInstance(handlerConfig);
         }
         catch (Exception e)
         {
            throw new FacesException(
                  "Unable to create Mojarra DecorateHandler delegate for s:decorate template",
                  e);
         }
      }
      return delegate;
   }

   private static ClassLoader resolveFacesImplClassLoader(FaceletContext context)
   {
      ClassLoader contextLoader = context.getClass().getClassLoader();
      if (canLoadDecorateHandler(contextLoader))
      {
         return contextLoader;
      }
      ClassLoader tccl = Thread.currentThread().getContextClassLoader();
      if (canLoadDecorateHandler(tccl))
      {
         return tccl;
      }
      ClassLoader facesApiLoader = FaceletContext.class.getClassLoader();
      if (canLoadDecorateHandler(facesApiLoader))
      {
         return facesApiLoader;
      }
      return contextLoader != null ? contextLoader : tccl;
   }

   private static boolean canLoadDecorateHandler(ClassLoader loader)
   {
      if (loader == null)
      {
         return false;
      }
      try
      {
         Class.forName(MOJARRA_DECORATE_HANDLER, false, loader);
         return true;
      }
      catch (ClassNotFoundException e)
      {
         return false;
      }
   }
}
