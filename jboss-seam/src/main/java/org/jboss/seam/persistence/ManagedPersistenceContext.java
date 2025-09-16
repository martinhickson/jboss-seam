//$Id: ManagedPersistenceContext.java 11990 2010-01-25 23:55:21Z manaRH $
package org.jboss.seam.persistence;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingException;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import jakarta.servlet.http.HttpSessionActivationListener;
import jakarta.servlet.http.HttpSessionEvent;
import javax.transaction.Synchronization;
import javax.transaction.SystemException;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Create;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.FlushModeType;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Unwrap;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.contexts.Lifecycle;
import org.jboss.seam.core.Mutable;
import org.jboss.seam.core.Expressions.ValueExpression;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;
import org.jboss.seam.transaction.Transaction;
import org.jboss.seam.transaction.UserTransaction;
import org.jboss.seam.util.Naming;

/**
 * A Seam component that manages a conversation-scoped extended
 * persistence context that can be shared by arbitrary other
 * components.
 * 
 * @author Gavin King
 */
@Scope(ScopeType.CONVERSATION)
@BypassInterceptors
@Install(false)
public class ManagedPersistenceContext 
   implements Serializable, HttpSessionActivationListener, Mutable, PersistenceContextManager, Synchronization
{
   private static final long serialVersionUID = -4972387440275848126L;
   private static final LogProvider log = Logging.getLogProvider(ManagedPersistenceContext.class);
   
   private transient EntityManager entityManager;
   private String persistenceUnitJndiName;
   private String componentName;
   private ValueExpression<EntityManagerFactory> entityManagerFactory;
   private List<Filter> filters = new ArrayList<Filter>(0);
   
   private transient boolean synchronizationRegistered;
   private transient boolean destroyed;
  
   public boolean clearDirty()
   {
      return true;
   }
   
   @Create
   public void create(Component component)
   {
      this.componentName = component.getName();
      if (persistenceUnitJndiName==null)
      {
         persistenceUnitJndiName = "java:/" + componentName;
      }
      
      PersistenceContexts.instance().touch(componentName);      
   }
   
   private void initEntityManager()
   {
      System.err.println("[SEAM-ENTITY-DEBUG] initEntityManager() called");
      System.err.println("[SEAM-ENTITY-DEBUG] this = " + this);
      System.err.println("[SEAM-ENTITY-DEBUG] persistenceUnitJndiName = '" + persistenceUnitJndiName + "'");
      System.err.println("[SEAM-ENTITY-DEBUG] componentName = '" + componentName + "'");
      System.err.println("[SEAM-ENTITY-DEBUG] entityManagerFactory = " + entityManagerFactory);
      System.err.println("[SEAM-ENTITY-DEBUG] filters.size() = " + filters.size());
      
      System.err.println("[SEAM-ENTITY-DEBUG] Getting EntityManagerFactory...");
      EntityManagerFactory emf = getEntityManagerFactoryFromJndiOrValueBinding();
      System.err.println("[SEAM-ENTITY-DEBUG] EntityManagerFactory obtained: " + emf);
      System.err.println("[SEAM-ENTITY-DEBUG] emf.getClass() = " + (emf != null ? emf.getClass().getName() : "null"));
      System.err.println("[SEAM-ENTITY-DEBUG] emf.isOpen() = " + (emf != null ? emf.isOpen() : "null"));
      
      System.err.println("[SEAM-ENTITY-DEBUG] Creating EntityManager from factory...");
      entityManager = emf.createEntityManager();
      System.err.println("[SEAM-ENTITY-DEBUG] EntityManager created: " + entityManager);
      System.err.println("[SEAM-ENTITY-DEBUG] entityManager.getClass() = " + (entityManager != null ? entityManager.getClass().getName() : "null"));
      System.err.println("[SEAM-ENTITY-DEBUG] entityManager.isOpen() = " + (entityManager != null ? entityManager.isOpen() : "null"));
      
      System.err.println("[SEAM-ENTITY-DEBUG] Getting PersistenceProvider...");
      PersistenceProvider persistenceProvider = PersistenceProvider.instance();
      System.err.println("[SEAM-ENTITY-DEBUG] PersistenceProvider obtained: " + persistenceProvider);
      System.err.println("[SEAM-ENTITY-DEBUG] persistenceProvider.getClass() = " + (persistenceProvider != null ? persistenceProvider.getClass().getName() : "null"));
      
      System.err.println("[SEAM-ENTITY-DEBUG] Proxying EntityManager...");
      entityManager = persistenceProvider.proxyEntityManager(entityManager);
      System.err.println("[SEAM-ENTITY-DEBUG] Proxied EntityManager: " + entityManager);
      System.err.println("[SEAM-ENTITY-DEBUG] proxied entityManager.getClass() = " + (entityManager != null ? entityManager.getClass().getName() : "null"));
      
      System.err.println("[SEAM-ENTITY-DEBUG] Getting PersistenceContexts...");
      PersistenceContexts persistenceContexts = PersistenceContexts.instance();
      System.err.println("[SEAM-ENTITY-DEBUG] PersistenceContexts obtained: " + persistenceContexts);
      System.err.println("[SEAM-ENTITY-DEBUG] persistenceContexts.getFlushMode() = " + (persistenceContexts != null ? persistenceContexts.getFlushMode() : "null"));
      
      System.err.println("[SEAM-ENTITY-DEBUG] Setting flush mode...");
      setEntityManagerFlushMode( persistenceContexts.getFlushMode() );
      System.err.println("[SEAM-ENTITY-DEBUG] Flush mode set successfully");

      System.err.println("[SEAM-ENTITY-DEBUG] Processing filters (" + filters.size() + " filters)...");
      for (Filter f: filters)
      {
         System.err.println("[SEAM-ENTITY-DEBUG] Processing filter: " + f + ", enabled: " + f.isFilterEnabled());
         if ( f.isFilterEnabled() )
         {
            persistenceProvider.enableFilter(f, entityManager);
            System.err.println("[SEAM-ENTITY-DEBUG] Filter enabled: " + f);
         }
      }

      System.err.println("[SEAM-ENTITY-DEBUG] initEntityManager() completed successfully");
      System.err.println("[SEAM-ENTITY-DEBUG] Final entityManager: " + entityManager);
      System.err.println("[SEAM-ENTITY-DEBUG] Final entityManager.isOpen(): " + (entityManager != null ? entityManager.isOpen() : "null"));

      if ( log.isDebugEnabled() )
      {
         if (entityManagerFactory==null)
         {
            log.debug("created seam managed persistence context for persistence unit: "+ persistenceUnitJndiName);
         }
         else 
         {
            log.debug("created seam managed persistence context from EntityManagerFactory");
         }
      }
   }
   
   @Unwrap
   public EntityManager getEntityManager() throws NamingException, SystemException
   {
      if (entityManager==null) initEntityManager();
      
      if ( !synchronizationRegistered && !Lifecycle.isDestroying() )
      {
         joinTransaction();
      }
      
      return entityManager;
   }

   private void joinTransaction() throws SystemException
   {
      UserTransaction transaction = Transaction.instance();
      if ( transaction.isActive() )
      {
         transaction.enlist(entityManager);
         try
         {
            transaction.registerSynchronization(this);
            synchronizationRegistered = true;
         }
         catch (Exception e)
         {
            synchronizationRegistered = PersistenceProvider.instance().registerSynchronization(this, entityManager);
         }
      }
   }
   
   /**
    * If a transaction is active, fail the passivation. The field holding the
    * managed EntityManager is marked as transient so that it is not serialized
    * (it can't be). The transient keyword was choosen because we don't want to
    * forcefully close and nullify the EntityManager on every request because
    * then we have to keep hitting the database to load the entities back into
    * the persistence context. The only downside is that we cannot clean up
    * on the old node before the session hops, but it turns out not to matter.
    * 
    * Note that we must use the method on the
    * {@link HttpSessionActivationListener} interface rather than
    * <code>@PrePassivate</code> since interceptors are disabled on this component.
    */
   public void sessionWillPassivate(HttpSessionEvent event)
   {
      if (synchronizationRegistered)
      {
         throw new IllegalStateException("cannot passivate persistence context with active transaction");
      }
   }
   
   /**
    * Note that we must use the method on the {@link HttpSessionActivationListener}
    * interface rather than @PostActivate since interceptors are disabled
    * on this component.
    */
   public void sessionDidActivate(HttpSessionEvent event) {}
   
   @Destroy
   public void destroy()
   {
      destroyed = true;
      if ( !synchronizationRegistered )
      {
         //in requests that come through SeamPhaseListener,
         //there can be multiple transactions per request,
         //but they are all completed by the time contexts
         //are destroyed
         //so wait until the end of the request to close
         //the session
         //on the other hand, if we are still waiting for
         //the transaction to commit, leave it open
         close();
      }
      PersistenceContexts.instance().untouch(componentName);
   }

   public void afterCompletion(int status)
   {
      synchronizationRegistered = false;
      //if ( !Contexts.isConversationContextActive() )
      if (destroyed)
      {
         //in calls to MDBs and remote calls to SBs, the 
         //transaction doesn't commit until after contexts
         //are destroyed, so wait until the transaction
         //completes before closing the session
         //on the other hand, if we still have an active
         //conversation context, leave it open
         close();
      }
   }
   
   public void beforeCompletion() {}
   
   private void close()
   {
      if (Contexts.isEventContextActive()) 
      {

         boolean transactionActive = false;
         
         try
         {
            UserTransaction tx = Transaction.instance();
            try 
            {
               transactionActive = tx.isActive();
            }
            catch (SystemException se)
            {
               log.debug("could not get transaction status while destroying persistence context");
            }
         }
         catch (Exception e)
         {
            // WebSphere throws a javax.naming.ConfigurationException when Transaction.instance() is called during HTTP Session expiration 
            // and there is no JNDI lookup possible. See details there: JBSEAM-4332
            log.warn("could not get transaction while destroying persistence context. (called during session expiration ?)");
         }
         
         if ( transactionActive )
         {
            throw new IllegalStateException("attempting to destroy the persistence context while an active transaction exists (try installing <transaction:ejb-transaction/>)");
         }
      }
      
      if ( log.isDebugEnabled() )
      {
         log.debug("destroying seam managed persistence context for persistence unit: " + persistenceUnitJndiName);
      }
      
      if (entityManager!=null && entityManager.isOpen())
      {
         entityManager.close();
      }
   }
   
   public EntityManagerFactory getEntityManagerFactoryFromJndiOrValueBinding()
   {
      System.err.println("[SEAM-ENTITY-DEBUG] getEntityManagerFactoryFromJndiOrValueBinding() called");
      System.err.println("[SEAM-ENTITY-DEBUG] this = " + this);
      System.err.println("[SEAM-ENTITY-DEBUG] this.getClass() = " + this.getClass().getName());
      System.err.println("[SEAM-ENTITY-DEBUG] entityManagerFactory value binding = " + entityManagerFactory);
      System.err.println("[SEAM-ENTITY-DEBUG] persistenceUnitJndiName = '" + persistenceUnitJndiName + "'");
      System.err.println("[SEAM-ENTITY-DEBUG] componentName = '" + componentName + "'");
      
      EntityManagerFactory result = null;
      //first try to find it via the value binding
      if (entityManagerFactory!=null)
      {
         System.err.println("[SEAM-ENTITY-DEBUG] Trying to get EntityManagerFactory from value binding");
         System.err.println("[SEAM-ENTITY-DEBUG] entityManagerFactory.getExpressionString() = " + entityManagerFactory.getExpressionString());
         try {
            result = entityManagerFactory.getValue();
            System.err.println("[SEAM-ENTITY-DEBUG] entityManagerFactory.getValue() returned: " + result);
            System.err.println("[SEAM-ENTITY-DEBUG] result.getClass() = " + (result != null ? result.getClass().getName() : "null"));
         } catch (Exception e) {
            System.err.println("[SEAM-ENTITY-ERROR] Exception getting value from entityManagerFactory: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
         }
      }
      else
      {
         System.err.println("[SEAM-ENTITY-DEBUG] No entityManagerFactory value binding configured - entityManagerFactory is null");
      }
      
      //if its not there, try JNDI
      if (result==null)
      {
         System.err.println("[SEAM-ENTITY-DEBUG] EntityManagerFactory not found via value binding, trying JNDI lookup");
         System.err.println("[SEAM-ENTITY-DEBUG] JNDI lookup target: '" + persistenceUnitJndiName + "'");
         
         Object lookedUp = null;
         try
         {
            System.err.println("[SEAM-ENTITY-DEBUG] Getting InitialContext...");
            javax.naming.InitialContext ctx = Naming.getInitialContext();
            System.err.println("[SEAM-ENTITY-DEBUG] InitialContext obtained: " + ctx);
            
            System.err.println("[SEAM-ENTITY-DEBUG] Performing JNDI lookup for: " + persistenceUnitJndiName);
            lookedUp = ctx.lookup(persistenceUnitJndiName);
            System.err.println("[SEAM-ENTITY-DEBUG] JNDI lookup returned: " + lookedUp);
            System.err.println("[SEAM-ENTITY-DEBUG] lookedUp.getClass() = " + (lookedUp != null ? lookedUp.getClass().getName() : "null"));
            
            result = (EntityManagerFactory) lookedUp;
            System.err.println("[SEAM-ENTITY-DEBUG] Cast to EntityManagerFactory successful: " + result);
            
         }
         catch (NamingException ne)
         {
            System.err.println("[SEAM-ENTITY-ERROR] NamingException during JNDI lookup: " + ne.getClass().getSimpleName() + ": " + ne.getMessage());
            System.err.println("[SEAM-ENTITY-ERROR] JNDI name attempted: '" + persistenceUnitJndiName + "'");
            System.err.println("[SEAM-ENTITY-ERROR] Full exception details:");
            ne.printStackTrace();
            throw new IllegalArgumentException("EntityManagerFactory not found in JNDI : " + persistenceUnitJndiName, ne);
         }
         catch (ClassCastException cce) {
            System.err.println("[SEAM-ENTITY-ERROR] ClassCastException - object found in JNDI is not an EntityManagerFactory");
            System.err.println("[SEAM-ENTITY-ERROR] Expected: EntityManagerFactory, Found: " + (lookedUp != null ? lookedUp.getClass().getName() : "null"));
            cce.printStackTrace();
            throw cce;
         }
         catch (Exception e) {
            System.err.println("[SEAM-ENTITY-ERROR] Unexpected exception during JNDI lookup: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Failed to lookup EntityManagerFactory from JNDI", e);
         }
      }
      
      System.err.println("[SEAM-ENTITY-DEBUG] Returning EntityManagerFactory: " + result);
      System.err.println("[SEAM-ENTITY-DEBUG] result.isOpen() = " + (result != null ? result.isOpen() : "null"));
      return result;
   }
   
   /**
    * A value binding expression that returns an EntityManagerFactory,
    * for use of JPA outside of Java EE 5 / Embeddable EJB3.
    */
   public ValueExpression<EntityManagerFactory> getEntityManagerFactory()
   {
      return entityManagerFactory;
   }
   
   public void setEntityManagerFactory(ValueExpression<EntityManagerFactory> entityManagerFactory)
   {
      this.entityManagerFactory = entityManagerFactory;
   }
   
   /**
    * The JNDI name of the EntityManagerFactory, for 
    * use of JPA in Java EE 5 / Embeddable EJB3.
    */
   public String getPersistenceUnitJndiName()
   {
      return persistenceUnitJndiName;
   }
   
   public void setPersistenceUnitJndiName(String persistenceUnitName)
   {
      this.persistenceUnitJndiName = persistenceUnitName;
   }
   
   public String getComponentName() 
   {
      return componentName;
   }
   
   /**
    * Hibernate filters to enable automatically
    */
   public List<Filter> getFilters()
   {
      return filters;
   }
   
   public void setFilters(List<Filter> filters)
   {
      this.filters = filters;
   }
   
   public void changeFlushMode(FlushModeType flushMode)
   {
      if (entityManager!=null && entityManager.isOpen())
      {
         setEntityManagerFlushMode(flushMode);
      }
   }
   
   protected void setEntityManagerFlushMode(FlushModeType flushMode)
   {
      switch (flushMode)
      {
         case AUTO:
            entityManager.setFlushMode(javax.persistence.FlushModeType.AUTO);
            break;
         case COMMIT:
            entityManager.setFlushMode(javax.persistence.FlushModeType.COMMIT);
            break;
         case MANUAL:
            PersistenceProvider.instance().setFlushModeManual(entityManager);
            break;
      }
   }
   
   @Override
   public String toString()
   {
      return "ManagedPersistenceContext(" + persistenceUnitJndiName + ")";
   }
}
