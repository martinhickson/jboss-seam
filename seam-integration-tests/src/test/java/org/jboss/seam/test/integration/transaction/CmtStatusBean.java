package org.jboss.seam.test.integration.transaction;

import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import javax.naming.InitialContext;
import jakarta.transaction.TransactionSynchronizationRegistry;

import org.jboss.seam.transaction.Transaction;
import org.jboss.seam.transaction.UserTransaction;

/**
 * Container-managed EJB used to assert Seam status queries are safe under CMT.
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CmtStatusBean implements CmtStatusLocal
{
   @Override
   public int seamStatus() throws Exception
   {
      return Transaction.instance().getStatus();
   }

   @Override
   public boolean seamActive() throws Exception
   {
      UserTransaction tx = Transaction.instance();
      return tx.isActive() && !tx.isNoTransaction();
   }

   @Override
   public int tsrStatus() throws Exception
   {
      TransactionSynchronizationRegistry tsr = (TransactionSynchronizationRegistry)
            new InitialContext().lookup("java:comp/TransactionSynchronizationRegistry");
      return tsr.getTransactionStatus();
   }

   @Override
   @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
   public int seamStatusNotSupported() throws Exception
   {
      return Transaction.instance().getStatus();
   }
}
