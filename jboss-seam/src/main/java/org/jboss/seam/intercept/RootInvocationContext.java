package org.jboss.seam.intercept;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.jboss.seam.util.Reflections;

/**
 * InvocationContext for use with CGLIB-based interceptors.
 * 
 * @author Gavin King
 *
 */
class RootInvocationContext implements InvocationContext
{
   private final Object bean;
   private final Method method;
   private Object[] params;
   private final Map contextData = new HashMap();

   public RootInvocationContext(Object bean, Method method, Object[] params)
   {
      this.bean = bean;
      this.method = method;
      this.params = params;
   }
   
   public Object proceed() throws Exception
   {
      Method targetMethod = resolveMethodForTarget(method, bean);
      targetMethod.setAccessible(true);
      return Reflections.invoke(targetMethod, bean, params);
   }

   private static Method resolveMethodForTarget(Method method, Object target)
   {
      for (Class<?> iface : target.getClass().getInterfaces())
      {
         try
         {
            return iface.getMethod(method.getName(), method.getParameterTypes());
         }
         catch (NoSuchMethodException ignored)
         {
         }
      }
      return method;
   }

   public Object getTarget()
   {
      return bean;
   }

   public Map getContextData()
   {
      return contextData;
   }

   public Method getMethod()
   {
      return method;
   }

   public Object[] getParameters()
   {
      return params;
   }

   public void setParameters(Object[] newParams)
   {
      params = newParams;
   }
}