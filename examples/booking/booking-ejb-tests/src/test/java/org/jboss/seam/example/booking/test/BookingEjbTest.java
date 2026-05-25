package org.jboss.seam.example.booking.test;

import java.util.Calendar;
import java.util.Date;

import jakarta.faces.model.DataModel;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OverProtocol;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.seam.Component;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.contexts.Lifecycle;
import org.jboss.seam.core.Manager;
import org.jboss.seam.example.booking.Booking;
import org.jboss.seam.example.booking.BookingList;
import org.jboss.seam.example.booking.Hotel;
import org.jboss.seam.example.booking.HotelBooking;
import org.jboss.seam.example.booking.HotelSearching;
import org.jboss.seam.example.booking.User;
import org.jboss.seam.security.Identity;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * In-container booking workflow using @Stateful EJB Seam components (EAR deployment).
 */
@RunWith(Arquillian.class)
public class BookingEjbTest {

    @Deployment(name = "BookingEjbTest")
    @OverProtocol("Servlet 5.0")
    public static Archive<?> createDeployment() throws Exception {
        return Deployments.bookingEarDeployment(BookingEjbTest.class);
    }

    @Before
    public void before() {
        Lifecycle.beginCall();
    }

    @After
    public void after() {
        if (Contexts.isConversationContextActive()) {
            Manager manager = Manager.instance();
            if (manager.isLongRunningConversation()) {
                manager.endConversation(false);
            }
        }
        Lifecycle.endCall();
    }

    @Test
    public void testBookHotelViaStatefulEjbs() throws Exception {
        Manager manager = Manager.instance();
        Identity identity = Identity.instance();
        HotelSearching hotelSearch = (HotelSearching) Component.getInstance("hotelSearch");
        HotelBooking hotelBooking = (HotelBooking) Component.getInstance("hotelBooking");
        BookingList bookingList = (BookingList) Component.getInstance("bookingList");

        manager.initializeTemporaryConversation();
        Contexts.getSessionContext().set("user", new User("Gavin King", "foobar", "gavin"));

        identity.setUsername("gavin");
        identity.setPassword("foobar");
        identity.login();

        hotelSearch.setSearchString("Union Square");
        hotelSearch.find();

        DataModel<?> hotels = (DataModel<?>) Contexts.getSessionContext().get("hotels");
        assertEquals(1, hotels.getRowCount());
        assertEquals("NY", ((Hotel) hotels.getRowData()).getCity());
        assertFalse(manager.isLongRunningConversation());

        hotelBooking.selectHotel((Hotel) hotels.getRowData());

        Hotel hotel = (Hotel) Contexts.getConversationContext().get("hotel");
        assertEquals("NY", hotel.getCity());
        assertEquals("10011", hotel.getZip());
        assertTrue(manager.isLongRunningConversation());

        hotelBooking.bookHotel();

        Booking booking = (Booking) Contexts.getConversationContext().get("booking");
        assertNotNull(booking.getUser());
        assertNotNull(booking.getHotel());
        assertNull(booking.getCreditCard());

        booking.setCreditCard("1234567891021234");
        booking.setCreditCardName("GAVIN KING");
        booking.setBeds(2);
        Date now = new Date();
        booking.setCheckinDate(now);
        booking.setCheckoutDate(now);

        hotelBooking.setBookingDetails();
        assertFalse(hotelBooking.isBookingValid());

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 2);
        booking.setCheckoutDate(cal.getTime());

        hotelBooking.setBookingDetails();
        assertTrue(hotelBooking.isBookingValid());

        hotelBooking.confirm();

        DataModel<?> bookings = (DataModel<?>) Contexts.getSessionContext().get("bookings");
        assertEquals(1, bookings.getRowCount());
        bookings.setRowIndex(0);
        booking = (Booking) bookings.getRowData();
        assertEquals("NY", booking.getHotel().getCity());
        assertEquals("gavin", booking.getUser().getUsername());
        assertFalse(manager.isLongRunningConversation());

        bookings.setRowIndex(0);
        bookingList.cancel();

        bookings = (DataModel<?>) Contexts.getSessionContext().get("bookings");
        assertEquals(0, bookings.getRowCount());
    }
}
