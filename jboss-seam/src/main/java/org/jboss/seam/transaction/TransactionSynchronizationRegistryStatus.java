package org.jboss.seam.transaction;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.naming.NamingException;
import javax.transaction.Status;
import javax.transaction.TransactionSynchronizationRegistry;

import org.jboss.seam.util.Naming;

/**
 * JTA transaction status via {@link TransactionSynchronizationRegistry}.
 * <p>
 * Safe to call from both CMT and BMT. Prefer this over
 * {@link javax.transaction.UserTransaction#getStatus()} or
 * {@link javax.ejb.EJBContext#getUserTransaction()}, which are restricted
 * under container-managed transactions.
 * <p>
 * The TSR JNDI reference is cached in an {@link AtomicReference} after the
 * first successful lookup; {@link TransactionSynchronizationRegistry#getTransactionStatus()}
 * is then a thread-local read.
 */
final class TransactionSynchronizationRegistryStatus
{
   private static final String TSR_JNDI_NAME = "java:comp/TransactionSynchronizationRegistry";

   private static final AtomicReference<TransactionSynchronizationRegistry> CACHED_TSR =
         new AtomicReference<TransactionSynchronizationRegistry>();
   /** True once JNDI was reachable and the name was absent (do not retry). */
   private static final AtomicBoolean ABSENT = new AtomicBoolean(false);

   private TransactionSynchronizationRegistryStatus() {}

   /**
    * @return status from the TSR, or {@code null} if the TSR cannot be looked up
    */
   static Integer getStatusOrNull()
   {
      TransactionSynchronizationRegistry tsr = CACHED_TSR.get();
      if (tsr == null && !ABSENT.get())
      {
         tsr = lookupAndCache();
      }
      if (tsr == null)
      {
         return null;
      }
      try
      {
         return tsr.getTransactionStatus();
      }
      catch (IllegalStateException e)
      {
         return Status.STATUS_NO_TRANSACTION;
      }
   }

   /**
    * @return TSR status, or {@link Status#STATUS_NO_TRANSACTION} if unavailable
    */
   static int getStatus()
   {
      Integer status = getStatusOrNull();
      return status != null ? status : Status.STATUS_NO_TRANSACTION;
   }

   private static TransactionSynchronizationRegistry lookupAndCache()
   {
      TransactionSynchronizationRegistry existing = CACHED_TSR.get();
      if (existing != null || ABSENT.get())
      {
         return existing;
      }
      try
      {
         TransactionSynchronizationRegistry tsr =
               (TransactionSynchronizationRegistry) Naming.getInitialContext().lookup(TSR_JNDI_NAME);
         if (CACHED_TSR.compareAndSet(null, tsr))
         {
            return tsr;
         }
         return CACHED_TSR.get();
      }
      catch (NamingException e)
      {
         // Name missing or JNDI up but unbound — do not keep retrying.
         ABSENT.set(true);
         return null;
      }
      catch (IllegalStateException e)
      {
         // Seam JNDI not initialized yet — retry on a later call.
         return null;
      }
   }
}
