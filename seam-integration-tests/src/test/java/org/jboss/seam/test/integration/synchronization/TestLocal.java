package org.jboss.seam.test.integration.synchronization;

import jakarta.ejb.Local;

@Local
public interface TestLocal
{
   public String test1();
   public String test2();
   public void remove();
}