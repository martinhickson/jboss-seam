package org.jboss.seam.test.integration.transaction;

import jakarta.transaction.Status;

import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Transactional;
import org.jboss.seam.transaction.Transaction;

@Name("transactionalStatusAction")
public class TransactionalStatusAction
{
   @Transactional
   public int seamStatus() throws Exception
   {
      return Transaction.instance().getStatus();
   }

   @Transactional
   public void markRollbackAndAssert() throws Exception
   {
      Transaction.instance().setRollbackOnly();
      int status = Transaction.instance().getStatus();
      if (status != Status.STATUS_MARKED_ROLLBACK && !Transaction.instance().isMarkedRollback())
      {
         throw new IllegalStateException("expected marked-rollback, got status=" + status);
      }
   }
}
