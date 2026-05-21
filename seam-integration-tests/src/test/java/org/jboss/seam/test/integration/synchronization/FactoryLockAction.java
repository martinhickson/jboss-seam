package org.jboss.seam.test.integration.synchronization;

import java.io.Serializable;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;

@Scope(ScopeType.SESSION)
@Name("factoryLock.test")
public class FactoryLockAction implements FactoryLockLocal, Serializable
{
   public String testOtherFactory() {
      try
      {
         Thread.sleep(500);
      }
      catch (InterruptedException e)
      {
         e.printStackTrace();
      }
      return (String)Component.getInstance("factoryLock.foo", true);
   }

   public String testSameFactory() {
      try
      {
         Thread.sleep(500);
      }
      catch (InterruptedException e)
      {
         e.printStackTrace();
      }
      return (String)Component.getInstance("factoryLock.testString", true);
   }

   @Factory(value="factoryLock.testString", scope=ScopeType.SESSION)
   public String getTestString() {
      return "testString";
   }

   public void remove() {}
}
