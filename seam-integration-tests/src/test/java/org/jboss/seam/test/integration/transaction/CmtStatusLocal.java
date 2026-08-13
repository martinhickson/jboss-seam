package org.jboss.seam.test.integration.transaction;

import jakarta.ejb.Local;

@Local
public interface CmtStatusLocal
{
   int seamStatus() throws Exception;

   boolean seamActive() throws Exception;

   int tsrStatus() throws Exception;

   int seamStatusNotSupported() throws Exception;
}
