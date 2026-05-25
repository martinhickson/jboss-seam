package org.jboss.seam.example.booking;

import jakarta.ejb.Local;

@Local
public interface BookingList {
    void getBookings();
    void cancel();
    void destroy();
}
