//$Id$
package org.jboss.seam;

import static org.jboss.seam.ComponentType.ENTITY_BEAN;
import static org.jboss.seam.ComponentType.JAVA_BEAN;
import static org.jboss.seam.ComponentType.MESSAGE_DRIVEN_BEAN;
import static org.jboss.seam.ComponentType.STATEFUL_SESSION_BEAN;
import static org.jboss.seam.ComponentType.STATELESS_SESSION_BEAN;
import static org.jboss.seam.util.EJB.MESSAGE_DRIVEN;
import static org.jboss.seam.util.EJB.STATEFUL;
import static org.jboss.seam.util.EJB.STATELESS;
import static org.jboss.seam.util.EJB.name;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.persistence.Entity;

import org.jboss.seam.annotations.Intercept;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Role;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.contexts.Lifecycle;
import org.jboss.seam.core.ServletSession;
import org.jboss.seam.init.DeploymentDescriptorInfo;
import org.jboss.seam.init.DeploymentDescriptorInfo.EjbInfo;
import org.jboss.seam.util.Strings;

/**
 * Convenience methods for accessing annotated information
 * about Seam component classes.
 * 
 * @author Gavin King
 */
public class Seam
{
   private static DeploymentDescriptorInfo deploymentInfo = new DeploymentDescriptorInfo();
    
   private static final Map<Class, String> COMPONENT_NAME_CACHE = new ConcurrentHashMap<Class, String>();

   /**
    * Get the default scope
    * @see Scope
    */
   public static ScopeType getComponentScope(Class<?> clazz)
   {
       return clazz.isAnnotationPresent(Scope.class) ?
               clazz.getAnnotation(Scope.class).value() :
               getComponentType(clazz).getDefaultScope();
   }
   
   /**
    * Get the scope for a role
    * @see Scope
    */
   public static ScopeType getComponentRoleScope(Class clazz, Role role)
   {
      return role.scope()==ScopeType.UNSPECIFIED ?
            getComponentType(clazz).getDefaultScope() :
            role.scope();
   }
   
   /**
    * Get the component type
    */
   public static ComponentType getComponentType(Class<?> clazz)
   {
      if (clazz.isAnnotationPresent(STATEFUL)) {
          return STATEFUL_SESSION_BEAN;
      } else if (clazz.isAnnotationPresent(STATELESS)) {
          return STATELESS_SESSION_BEAN;
      } else if (clazz.isAnnotationPresent(MESSAGE_DRIVEN)) {
          return MESSAGE_DRIVEN_BEAN;
      } else if (clazz.isAnnotationPresent(Entity.class)) {
          return ENTITY_BEAN;
      } else {          
          EjbInfo info = deploymentInfo.getBeanByClass(clazz.getName());
          if (info != null) {
              return info.getBeanType();
          }
          
          return JAVA_BEAN;
      }      
   }
   
   /**
    * Get the component name
    * @see Name
    */
   public static String getComponentName(Class<?> clazz)
   {
      String result = COMPONENT_NAME_CACHE.get(clazz);
      if (result==null)
      {
         result = searchComponentName(clazz);
         if (result!=null)
         {
            COMPONENT_NAME_CACHE.put(clazz, result);
         }
      }
      return result;
   }
   
   public static String searchComponentName(Class<?> clazz)
   {
      while ( clazz!=null && !Object.class.equals(clazz) )
      {
         Name name = clazz.getAnnotation(Name.class);
         if ( name!=null ) return name.value();
         clazz = clazz.getSuperclass();
      }
      return null;
   }
   
   /**
    * Get the bean class from a container-generated proxy
    * class BROKEN!!!!!
    */
   /*public static Class getBeanClass(Class<?> clazz)
   {
      while ( clazz!=null && !Object.class.equals(clazz) )
      {
         Name name = clazz.getAnnotation(Name.class);
         if ( name!=null ) return clazz;
         clazz = clazz.getSuperclass();
      }
      return null;
   }*/
   
   /**
    * Get the bean class from a container-generated proxy
    * class
    */
   public static Class getEntityClass(Class<?> clazz)
   {
      while ( clazz!=null && !Object.class.equals(clazz) )
      {
         Entity name = clazz.getAnnotation(Entity.class);
         if ( name!=null ) return clazz;
         clazz = clazz.getSuperclass();
      }
      return null;
   }
   
   /**
    * Is the class a container-generated proxy class for an 
    * entity bean?
    */
   public static boolean isEntityClass(Class<?> clazz)
   {
      while ( clazz!=null && !Object.class.equals(clazz) )
      {
         if ( clazz.isAnnotationPresent(Entity.class) )
         {
            return true;
         }
         clazz = clazz.getSuperclass();
      }
      return false;
   }
   
   public static String getEjbName(Class<?> clazz)
   {
       switch (getComponentType(clazz)) {
           case ENTITY_BEAN:
           case JAVA_BEAN:
               return null;
           case STATEFUL_SESSION_BEAN:
               if (clazz.isAnnotationPresent(STATEFUL)) {
                   String statefulName = name(clazz.getAnnotation(STATEFUL));
                   return statefulName.equals("") ? unqualifyClassName(clazz) : statefulName;
               } else {
                   EjbInfo info = deploymentInfo.getBeanByClass(clazz.getName()); 
                   return info.getName();                   
               }
           case STATELESS_SESSION_BEAN:
               if (clazz.isAnnotationPresent(STATELESS)) {
                   String statelessName = name(clazz.getAnnotation(STATELESS));
                   return statelessName.equals("") ? unqualifyClassName(clazz) : statelessName;
               } else {
                   EjbInfo info = deploymentInfo.getBeanByClass(clazz.getName()); 
                   return info.getName();
               }
           case MESSAGE_DRIVEN_BEAN:
               if (clazz.isAnnotationPresent(MESSAGE_DRIVEN)) {
                   String mdName = name(clazz.getAnnotation(MESSAGE_DRIVEN));
                   return mdName.equals("") ? unqualifyClassName(clazz) : mdName;
               } else {
                   EjbInfo info = deploymentInfo.getBeanByClass(clazz.getName()); 
                   return info.getName();
               }
           default:
               throw new IllegalArgumentException();
       }
   }
   private static String unqualifyClassName(Class<?> clazz) {
      return Strings.unqualify( Strings.unqualify( clazz.getName() ), '$' );
   }
   
   public static InterceptionType getInterceptionType(Class<?> clazz)
   {
      ComponentType componentType = getComponentType(clazz);
      if ( componentType==ENTITY_BEAN )
      {
         return InterceptionType.NEVER;
      }
      else if ( getComponentType(clazz)==MESSAGE_DRIVEN_BEAN )
      {
         return InterceptionType.ALWAYS;
      }
      else if ( clazz.isAnnotationPresent(Intercept.class) )
      {
         return clazz.getAnnotation(Intercept.class).value();
      }
      else 
      {
         return InterceptionType.ALWAYS;
      }
   }
   /**
    * Mark the session for invalidation at the end of the 
    * request cycle
    * 
    * @deprecated use Session.instance().invalidate()
    */
   public static void invalidateSession()
   {
      ServletSession.instance().invalidate();
   }
   
   /**
    * Is the session marked for invalidation?
    * 
    * @deprecated use Session.instance().isInvalidated()
    */
   public static boolean isSessionInvalid()
   {
      return ServletSession.instance().isInvalid();
   }
   
   /**
    * Get the Seam component, even if no application context
    * is associated with the current thread.
    */
   public static Component componentForName(String name)
   {
      if ( Contexts.isApplicationContextActive() )
      {
         return Component.forName(name);
      }
      else
      {
         Lifecycle.mockApplication();
         try
         {
            return Component.forName(name);
         }
         finally
         {
            Lifecycle.unmockApplication();
         }
      }
   }
   
   public static String getVersion()
   {
      Package pkg = Seam.class.getPackage();
      return (pkg != null ? pkg.getImplementationVersion() : null);      
   }
  
       
   
   
   public static void clearComponentNameCache()
   {
      COMPONENT_NAME_CACHE.clear();
   }
}
