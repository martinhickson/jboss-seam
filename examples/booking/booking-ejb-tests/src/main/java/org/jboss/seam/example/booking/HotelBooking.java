package org.jboss.seam.example.booking;

import jakarta.ejb.Local;

@Local
public interface HotelBooking {
    void selectHotel(Hotel selectedHotel);
    void bookHotel();
    void setBookingDetails();
    boolean isBookingValid();
    void confirm();
    void cancel();
    void destroy();
}
