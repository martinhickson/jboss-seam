package org.jboss.seam.example.booking;

import jakarta.ejb.Local;

@Local
public interface Authenticator {
    boolean authenticate();
}
