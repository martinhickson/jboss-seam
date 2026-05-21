package org.jboss.seam.test.integration.synchronization;

import java.io.Serializable;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Synchronized;

@Scope(ScopeType.SESSION)
@Name("test")
@Synchronized(timeout=10000)
public class TestAction implements TestLocal, Serializable
{
   public String test1() {
      try
      {
         Thread.sleep(100);
      }
      catch (InterruptedException e)
      {
         e.printStackTrace();
      }
      return "test1";
   }

   public String test2() {
      try
      {
         Thread.sleep(100);
      }
      catch (InterruptedException e)
      {
         e.printStackTrace();
      }
      return "test2";
   }

   public void remove() {}
}
