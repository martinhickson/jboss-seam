package org.jboss.seam.example.booking;

import java.io.Serializable;
import java.util.List;
import jakarta.ejb.Stateful;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.annotations.datamodel.DataModelSelection;

/**
 * Seam component for managing booking lists
 */
@Stateful
@Name("bookingList")
@Scope(ScopeType.SESSION)
public class BookingList implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @PersistenceContext
    private EntityManager em;
    
    @In
    private User user;
    
    @DataModel
    private List<Booking> bookings;
    
    @DataModelSelection
    private Booking selectedBooking;
    
    @Factory("bookings")
    public void getBookings() {
        bookings = em.createQuery(
            "select b from Booking b where b.user.username = :username order by b.checkinDate", 
            Booking.class)
            .setParameter("username", user.getUsername())
            .getResultList();
    }
    
    public void cancel() {
        em.remove(selectedBooking);
        getBookings();
    }
    
    public List<Booking> getBookingsList() {
        return bookings;
    }
    
    public Booking getSelectedBooking() {
        return selectedBooking;
    }
    
    public void setSelectedBooking(Booking selectedBooking) {
        this.selectedBooking = selectedBooking;
    }
    
    public void destroy() {
        // Clean up
    }
}
