package org.jboss.seam.test.integration.synchronization;

public interface FactoryLockLocal
{
   String getTestString();
   String testOtherFactory();
   String testSameFactory();
   void remove();
}
