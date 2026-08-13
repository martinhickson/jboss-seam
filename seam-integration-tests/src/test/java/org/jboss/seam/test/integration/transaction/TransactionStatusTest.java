package org.jboss.seam.test.integration.transaction;

import javax.naming.InitialContext;
import jakarta.transaction.Status;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OverProtocol;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.seam.mock.JUnitSeamTest;
import org.jboss.seam.test.integration.Deployments;
import org.jboss.seam.transaction.Transaction;
import org.jboss.seam.transaction.UserTransaction;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Verifies Seam transaction status queries use TSR safely under JTA / CMT on WildFly.
 */
@RunWith(Arquillian.class)
public class TransactionStatusTest extends JUnitSeamTest
{
   @Deployment(name = "TransactionStatusTest")
   @OverProtocol("Servlet 5.0")
   public static Archive<?> createDeployment()
   {
      return Deployments.defaultSeamDeployment(
            "WEB-INF/components.xml",
            TransactionStatusTest.class,
            TransactionalStatusAction.class,
            CmtStatusBean.class,
            CmtStatusLocal.class);
   }

   private CmtStatusLocal lookupCmtBean() throws Exception
   {
      InitialContext ctx = new InitialContext();
      try
      {
         return (CmtStatusLocal) ctx.lookup("java:module/CmtStatusBean!org.jboss.seam.test.integration.transaction.CmtStatusLocal");
      }
      catch (Exception ignored)
      {
         return (CmtStatusLocal) ctx.lookup("java:global/seam-it-transactionstatustest/CmtStatusBean!org.jboss.seam.test.integration.transaction.CmtStatusLocal");
      }
   }

   @Test
   public void getStatusDoesNotThrowOutsideTransaction() throws Exception
   {
      new ComponentTest()
      {
         @Override
         protected void testComponents() throws Exception
         {
            UserTransaction tx = Transaction.instance();
            int status = tx.getStatus();
            Assert.assertTrue(
                  "expected inactive status, got " + status,
                  status == Status.STATUS_NO_TRANSACTION
                        || status == Status.STATUS_COMMITTED
                        || status == Status.STATUS_ROLLEDBACK
                        || !tx.isActive());
            Assert.assertFalse(tx.isActive());
         }
      }.run();
   }

   @Test
   public void getStatusActiveInsidePojoTransactional() throws Exception
   {
      new ComponentTest()
      {
         @Override
         protected void testComponents() throws Exception
         {
            TransactionalStatusAction action =
                  (TransactionalStatusAction) getInstance("transactionalStatusAction");
            Assert.assertEquals(Status.STATUS_ACTIVE, action.seamStatus());
         }
      }.run();
   }

   @Test
   public void getStatusActiveInsideCmtEjb() throws Exception
   {
      new ComponentTest()
      {
         @Override
         protected void testComponents() throws Exception
         {
            CmtStatusLocal bean = lookupCmtBean();
            Assert.assertEquals(Status.STATUS_ACTIVE, bean.seamStatus());
            Assert.assertTrue(bean.seamActive());
            Assert.assertEquals(Status.STATUS_ACTIVE, bean.tsrStatus());
         }
      }.run();
   }

   @Test
   public void getStatusFromCmtNotSupportedDoesNotThrow() throws Exception
   {
      new ComponentTest()
      {
         @Override
         protected void testComponents() throws Exception
         {
            CmtStatusLocal bean = lookupCmtBean();
            Assert.assertEquals(Status.STATUS_NO_TRANSACTION, bean.seamStatusNotSupported());
         }
      }.run();
   }

   @Test
   public void setRollbackOnlyVisibleViaStatus() throws Exception
   {
      new ComponentTest()
      {
         @Override
         protected void testComponents() throws Exception
         {
            TransactionalStatusAction action =
                  (TransactionalStatusAction) getInstance("transactionalStatusAction");
            action.markRollbackAndAssert();
         }
      }.run();
   }
}
