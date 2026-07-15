package org.jboss.seam.el;

import java.beans.FeatureDescriptor;
import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import jakarta.el.BeanELResolver;
import jakarta.el.ELContext;
import jakarta.el.ELResolver;
import jakarta.el.MethodNotFoundException;
import jakarta.el.PropertyNotFoundException;

/**
 * Jakarta Faces 4 / EL 5+ resolves {@code #{bean.actionMethod}} as a property unless
 * parentheses are used. Seam 2 pages and components use the legacy form
 * {@code #{identity.logout}} on actions. This resolver exposes accessible
 * zero-argument methods as deferred bindings without invoking them during render.
 */
public class SeamBeanELResolver extends ELResolver
{
   private final BeanELResolver delegate = new BeanELResolver();

   @Override
   public Object getValue(ELContext context, Object base, Object property)
   {
      if (base == null || property == null || isMapOrListAccess(base))
      {
         return null;
      }

      try
      {
         Object value = delegate.getValue(context, base, property);
         if (context.isPropertyResolved())
         {
            return value;
         }
      }
      catch (PropertyNotFoundException ignored)
      {
      }

      if (property instanceof String)
      {
         Method method = findZeroArgMethod(base.getClass(), (String) property);
         if (method != null)
         {
            context.setPropertyResolved(true);
            return new SeamDeferredMethodBinding(base, method);
         }
      }

      return null;
   }

   @Override
   public Class<?> getType(ELContext context, Object base, Object property)
   {
      if (base == null || property == null || isMapOrListAccess(base))
      {
         return null;
      }
      try
									   
      {
      Class<?> type = delegate.getType(context, base, property);
      if (context.isPropertyResolved())
      {
         return type;
      }
      }
      catch (PropertyNotFoundException ignored)
      {
      }
      if (property instanceof String && findZeroArgMethod(base.getClass(), (String) property) != null)
      {
         context.setPropertyResolved(true);
         return Object.class;
      }
      return null;
   }

   @Override
   public void setValue(ELContext context, Object base, Object property, Object value)
   {
      if (base == null || property == null || isMapOrListAccess(base))
      {
         return;
      }
      try
      {
      delegate.setValue(context, base, property, value);
   }
      catch (PropertyNotFoundException ignored)
      {
      }
   }

   @Override
   public boolean isReadOnly(ELContext context, Object base, Object property)
   {
      if (base == null || property == null || isMapOrListAccess(base))
      {
         return false;
      }
      if (delegate.isReadOnly(context, base, property))
      {
         return true;
      }
      return property instanceof String && findZeroArgMethod(base.getClass(), (String) property) != null;
   }

   @Override
   public Object invoke(ELContext context, Object base, Object method, Class<?>[] paramTypes, Object[] params)
   {
      if (base instanceof SeamDeferredMethodBinding)
      {
         SeamDeferredMethodBinding binding = (SeamDeferredMethodBinding) base;
         if (method == null || binding.getMethod().getName().equals(method))
         {
            context.setPropertyResolved(true);
            return binding.invoke();
         }
      }
      return delegate.invoke(context, base, method, paramTypes, params);
   }

   @Override
   public Class<?> getCommonPropertyType(ELContext context, Object base)
   {
      return delegate.getCommonPropertyType(context, base);
   }

   public Iterator<FeatureDescriptor> getFeatureDescriptors(ELContext context, Object base)
   {
      return null;
   }

   private static boolean isMapOrListAccess(Object base)
   {
      return base instanceof Map || base instanceof List;
   }

   private static Method findZeroArgMethod(Class<?> type, String name)
   {
      for (Method method : type.getMethods())
      {
         if (method.getName().equals(name) && method.getParameterTypes().length == 0)
         {
            return method;
         }
      }
      return null;
   }

   /**
    * Placeholder for a no-arg method reference; invoked only via {@link #invoke}.
    */
   public static final class SeamDeferredMethodBinding
   {
      private final Object target;
      private final Method method;

      SeamDeferredMethodBinding(Object target, Method method)
      {
         this.target = target;
         this.method = method;
      }

      Method getMethod()
      {
         return method;
      }

      Object invoke()
      {
         try
         {
            return method.invoke(target);
         }
         catch (Exception e)
         {
            throw new MethodNotFoundException("Unable to invoke " + method.getName(), e);
         }
      }
   }
}
