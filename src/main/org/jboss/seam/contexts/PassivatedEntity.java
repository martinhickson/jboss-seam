package org.jboss.seam.contexts;

import java.io.Serializable;

import javax.persistence.EntityManager;

import org.hibernate.Session;
import org.jboss.seam.Component;
import org.jboss.seam.Seam;
import org.jboss.seam.core.PersistenceContexts;
import org.jboss.seam.persistence.PersistenceProvider;
import org.jboss.seam.transaction.Transaction;

/**
 * A swizzled entity reference, consisting of the class,
 * id and persistence context name.
 * 
 * @see EntityBean
 * @see org.jboss.seam.interceptors.ManagedEntityIdentityInterceptor
 * 
 * @author Gavin King
 *
 */
public class PassivatedEntity implements Serializable
{
   private static final long serialVersionUID = 6565440294007267788L;
   
   private Object id;
   private String persistenceContext;
   private Class<?> entityClass; //TODO: make this transient, and serialize only the class name..
   
   private PassivatedEntity(Object id, Class<?> entityClass, String persistenceContext)
   {
      this.id = id;
      this.persistenceContext = persistenceContext;
      this.entityClass = entityClass;
   }
   
   public String getPersistenceContext()
   {
      return persistenceContext;
   }
   
   public Object getId()
   {
      return id;
   }
   
   public Class<?> getEntityClass()
   {
      return entityClass;
   }

   public Object toEntityReference()
   {
      Object persistenceContext = Component.getInstance( getPersistenceContext() );
      if ( persistenceContext==null )
      {
         return null;
      }
      else
      {
         if (persistenceContext instanceof EntityManager)
         {
            EntityManager em = (EntityManager) persistenceContext;
            return em.isOpen() ? 
                     em.getReference( getEntityClass(), getId() ) : null;
         }
         else
         {
            Session session = (Session) persistenceContext;
            return session.isOpen() ? 
                     session.load( getEntityClass(), (Serializable) getId() ) : null;
         }
      }
   }

   public static PassivatedEntity createPassivatedEntity(Object value)
   {
      Class entityClass = Seam.getEntityClass( value.getClass() );
      if (entityClass!=null)
      {
         for ( String persistenceContextName: PersistenceContexts.instance().getTouchedContexts() )
         {
            Object persistenceContext = Component.getInstance(persistenceContextName);
            boolean managed;
            Object id;
            if (persistenceContext instanceof EntityManager)
            {
               EntityManager em = (EntityManager) persistenceContext;
               try
               {
                  managed = em.isOpen() && em.contains(value);
               }
               catch (RuntimeException re) 
               {
                  //workaround for bug in HEM! //TODO; deleteme
                  managed = false;
               }
               id = managed ? PersistenceProvider.instance().getId(value, em) : null;
            }
            else
            {
               Session session = (Session) persistenceContext;
               try
               {
                  managed = session.isOpen() && session.contains(value);
               }
               catch (RuntimeException re) 
               {
                  //just in case! //TODO; deleteme
                  managed = false;
               }
               id = managed ? session.getIdentifier(value) : null;
            }
            if (managed)
            {
               if (id==null)
               {
                  //this can happen if persist() fails in Hibernate
                  return null;
               }
               else
               {
                  return new PassivatedEntity(id, entityClass, persistenceContextName);
               }
            }
         }
      }
      return null;
   }
   
   public static boolean isTransactionRolledBackOrMarkedRollback()
   {
      try
      {
         return Transaction.instance().isRolledBackOrMarkedRollback();
      }
      catch (Exception e)
      {
         return false;
      }
   }
   
   @Override
   public String toString()
   {
      return entityClass + "#" + id;
   }
   
}