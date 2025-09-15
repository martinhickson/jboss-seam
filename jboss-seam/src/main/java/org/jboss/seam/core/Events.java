package org.jboss.seam.core;

import static org.jboss.seam.annotations.Install.BUILT_IN;

import java.util.List;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.async.AbstractDispatcher;
import org.jboss.seam.async.CronSchedule;
import org.jboss.seam.async.Dispatcher;
import org.jboss.seam.async.Schedule;
import org.jboss.seam.async.TimerSchedule;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.core.Expressions.MethodExpression;
import org.jboss.seam.core.Init.ObserverMethod;
import org.jboss.seam.core.Init.ObserverMethodExpression;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;

/**
 * Support for Seam component-driven events
 * 
 * @author Gavin King
 *
 */
@Scope(ScopeType.EVENT)
@BypassInterceptors
@Name("org.jboss.seam.core.events")
@Install(precedence=BUILT_IN)
public class Events 
{
   
   private static final LogProvider log = Logging.getLogProvider(Events.class);
   
   /**
    * Add a new listener for a given event type
    * 
    * @param type the event type
    * @param methodBindingExpression a method binding, expressed in EL
    * @param argTypes the argument types of the method binding
    */
   public void addListener(String type, String methodBindingExpression, Class... argTypes)
   {
      MethodExpression methodBinding = Expressions.instance().createMethodExpression(methodBindingExpression, Object.class, argTypes);
      Init.instance().addObserverMethodExpression(type, methodBinding);
   }
   
   /**
    * Raise an event that is to be processed synchronously
    * 
    * @param type the event type
    * @param parameters parameters to be passes to the listener method
    */
   public void raiseEvent(String type, Object... parameters)
   {
      //TODO: find a way to map event parameters to params in an EL-defined listener
      log.trace("Processing event:" + type);
      List<Init.ObserverMethodExpression> list = Init.instance().getObserverMethodExpressions(type);
      if (list!=null)
      {
         for (ObserverMethodExpression listener: list )
         {
            listener.getMethodBinding().invoke(parameters);
         }
      }
      List<Init.ObserverMethod> observers = Init.instance().getObserverMethods(type);
      if (observers!=null)
      {
         for (ObserverMethod observer: observers)
         {
            String name = observer.getComponent().getName();
            Object listener = Component.getInstance( name, observer.isCreate(), false );
            if ( observer.getComponent().hasUnwrapMethod() )
            {
               listener = observer.getComponent().getScope().getContext().get(name);
            }
            
            if (listener!=null)
            {
               observer.getComponent().callComponentMethod(listener, observer.getMethod(), parameters);
            }
         }
      }
   }
   
   /**
    * Raise an event that is to be processed asynchronously
    * 
    * @param type the event type
    * @param parameters parameters to be passes to the listener method
    */
   public void raiseAsynchronousEvent(String type, Object... parameters)
   {
      getDispatcher().scheduleAsynchronousEvent(type, parameters);
   }

   /**
    * Raise an event that is to be processed according to a "schedule"
    * 
    * @see TimerSchedule (EJB, quartz or JDK timer service)
    * @see CronSchedule (quartz timer service only)
    * 
    * @param type the event type
    * @param schedule the schedule object, specific to the dispatcher strategy
    * @param parameters parameters to be passes to the listener method
    */
   public void raiseTimedEvent(String type, Schedule schedule, Object... parameters)
   {
      getDispatcher().scheduleTimedEvent(type, schedule, parameters);
   }
   
   /**
    * Raise an event that is to be processed after successful completion of 
    * the current transaction
    * 
    * @param type the event type
    * @param parameters parameters to be passes to the listener method
    */
   public void raiseTransactionSuccessEvent(String type, Object... parameters)
   {
      getDispatcher().scheduleTransactionSuccessEvent(type, parameters);
   }
   
   /**
    * Raise an event that is to be processed after the current transaction
    * ends
    * 
    * @param type the event type
    * @param parameters parameters to be passes to the listener method
    */
   public void raiseTransactionCompletionEvent(String type, Object... parameters)
   {
      getDispatcher().scheduleTransactionCompletionEvent(type, parameters);
   }
   
   /**
    * @return the Dispatcher object to use for dispatching asynchronous
    * and timed events
    */
   protected Dispatcher getDispatcher()
   {
      return AbstractDispatcher.instance();
   }
   
   public static boolean exists()
   {
      log.info("Events.exists() called - checking if event context is active");
      boolean eventContextActive = Contexts.isEventContextActive();
      log.info("Events.exists() - event context active: " + eventContextActive);
      
      if (!eventContextActive) {
         log.warn("Events.exists() - event context is NOT active, returning false");
         return false;
      }
      
      Events eventsInstance = instance();
      boolean instanceNotNull = eventsInstance != null;
      log.info("Events.exists() - instance is not null: " + instanceNotNull);
      
      return eventContextActive && instanceNotNull;
   }

   public static Events instance()
   {
      log.info("Events.instance() called - attempting to get Events component");
      
      // Check if event context is active first
      boolean eventContextActive = Contexts.isEventContextActive();
      log.info("Events.instance() - event context active: " + eventContextActive);
      
      if (!eventContextActive) {
         log.warn("Events.instance() - event context is NOT active, this may cause Component.getInstance to return null");
      }
      
      try {
         log.info("Events.instance() - calling Component.getInstance(Events.class, ScopeType.EVENT)");
         Events result = (Events) Component.getInstance(Events.class, ScopeType.EVENT);
         
         if (result == null) {
            log.error("Events.instance() - Component.getInstance returned NULL!");
            log.error("Events.instance() - Event context active: " + eventContextActive);
            log.error("Events.instance() - Current contexts: " + Contexts.toString());
            
            // Try to get more information about why it's null
            try {
               Component eventsComponent = Component.forClass(Events.class);
               log.error("Events.instance() - Events component definition: " + (eventsComponent != null ? eventsComponent.toString() : "NULL"));
               if (eventsComponent != null) {
                  log.error("Events.instance() - Events component scope: " + eventsComponent.getScope());
                  log.error("Events.instance() - Events component name: " + eventsComponent.getName());
                  log.error("Events.instance() - Events component installed: " + eventsComponent.isInstalled());
               }
            } catch (Exception e) {
               log.error("Events.instance() - Error getting component info: " + e.getMessage(), e);
            }
         } else {
            log.info("Events.instance() - Successfully retrieved Events instance: " + result.getClass().getName());
         }
         
         return result;
         
      } catch (Exception e) {
         log.error("Events.instance() - Exception occurred while getting Events instance: " + e.getMessage(), e);
         log.error("Events.instance() - Exception stack trace follows:");
         e.printStackTrace();
         throw e;
      }
   }
   
}
