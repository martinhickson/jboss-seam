package org.jboss.seam.example.booking;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Date;
import jakarta.persistence.EntityManager;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Begin;
import org.jboss.seam.annotations.End;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Transactional;
import org.jboss.seam.core.Events;
import org.jboss.seam.core.Manager;
// import org.jboss.seam.faces.FacesMessages;

/**
 * Seam component for hotel booking functionality
 */
@Name("hotelBooking")
@Scope(ScopeType.CONVERSATION)
@Transactional
public class HotelBooking implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @In
    private EntityManager entityManager;
    
    @In
    private User user;
    
    @In
    private Events events;
    
    @In(required = false)
    @Out
    private Hotel hotel;
    
    @In(required = false)
    @Out(required = false)
    private Booking booking;
    
    private boolean bookingValid;
    
    @Begin
    public void selectHotel(Hotel selectedHotel) {
        hotel = entityManager.find(Hotel.class, selectedHotel.getId());
    }
    
    public void bookHotel() {
        booking = new Booking(hotel, user);
        Calendar calendar = Calendar.getInstance();
        booking.setCheckinDate(calendar.getTime());
        calendar.add(Calendar.DAY_OF_MONTH, 1);
        booking.setCheckoutDate(calendar.getTime());
        booking.setBeds(1);
        booking.setSmoking(false);
        Calendar expiry = Calendar.getInstance();
        booking.setCreditCardExpiryMonth(expiry.get(Calendar.MONTH) + 1);
        booking.setCreditCardExpiryYear(expiry.get(Calendar.YEAR) + 1);
    }
    
    public void setBookingDetails() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, -1);
        
        if (booking.getCheckinDate().before(calendar.getTime())) {
            // FacesMessages.instance().addToControl("checkinDate", "Check in date must be a future date");
            System.out.println("Validation error: Check in date must be a future date");
            bookingValid = false;
        } else if (!booking.getCheckinDate().before(booking.getCheckoutDate())) {
            // FacesMessages.instance().addToControl("checkoutDate", "Check out date must be later than check in date");
            System.out.println("Validation error: Check out date must be later than check in date");
            bookingValid = false;
        } else {
            bookingValid = true;
        }
    }
    
    public boolean isBookingValid() {
        return bookingValid;
    }
    
    @End
    public void confirm() {
        entityManager.persist(booking);
        events.raiseTransactionSuccessEvent("bookingConfirmed");
        System.out.println("Booking confirmed for " + user.getName() + " at " + hotel.getName());
        Manager.instance().endConversation(false);
    }
    
    @End
    public void cancel() {
        Manager.instance().endConversation(false);
    }
}
