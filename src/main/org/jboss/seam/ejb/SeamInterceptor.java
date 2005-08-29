/*
  * JBoss, Home of Professional Open Source
  *
  * Distributable under LGPL license.
  * See terms of license at gnu.org.
  */
package org.jboss.seam.ejb;

import javax.ejb.AroundInvoke;
import javax.ejb.InvocationContext;

import org.jboss.logging.Logger;
import org.jboss.seam.Component;
import org.jboss.seam.Seam;
import org.jboss.seam.core.Manager;
import org.jboss.seam.interceptors.SeamInvocationContext;

/**
 * Interceptor for bijection and conversation scope management
 * for a session bean component
 * 
 * @author Gavin King
 * @version $Revision$
 */
public class SeamInterceptor
{
   
   private static final Logger log = Logger.getLogger(SeamInterceptor.class);
   
   @AroundInvoke
   public Object aroundInvoke(InvocationContext invocation) throws Exception
   {
      final Component component = getSeamComponent( invocation.getBean() );
      if ( Manager.instance().isProcessInterceptors() )
      {
         log.info("intercepted: " + invocation.getMethod().getName());
         return new SeamInvocationContext(invocation, component).proceed();
      }
      else {
         log.debug("not intercepted: " + invocation.getMethod().getName());
         component.inject( invocation.getBean(), false );
         return invocation.proceed();
      }
   }

   private Component getSeamComponent(Object bean)
   {
      return Component.forName(Seam.getComponentName( bean.getClass() ));
   }
   
}
