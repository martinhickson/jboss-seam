//$Id: BookingTest.java 5810 2007-07-16 06:46:47Z gavin $
package org.jboss.seam.example.booking.test;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.jboss.arquillian.container.test.api.Deployment;
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
import org.jboss.shrinkwrap.api.spec.WebArchive;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
public class BookingTest {

    @Deployment(name = "BookingTest")
    public static Archive<?> createDeployment() throws Exception {
        return Deployments.bookingDeployment()
                .addClass(BookingTest.class);
    }

    @Before
    public void before() {
        Lifecycle.beginCall();
        Manager.instance().initializeTemporaryConversation();
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
    public void testBookHotel() throws Exception {
        Manager manager = Manager.instance();
        Identity identity = Identity.instance();
        HotelSearching hotelSearch = (HotelSearching) Component.getInstance("hotelSearch");
        HotelBooking hotelBooking = (HotelBooking) Component.getInstance("hotelBooking");
        BookingList bookingList = (BookingList) Component.getInstance("bookingList");

        Contexts.getSessionContext().set("user", new User("Gavin King", "foobar", "gavin"));

        identity.setUsername("gavin");
        identity.setPassword("foobar");
        identity.login();

        hotelSearch.setSearchString("Union Square");
        hotelSearch.find();

        List<Hotel> hotels = hotelSearch.getHotels();
        assertEquals(1, hotels.size());
        assertEquals("NY", hotels.get(0).getCity());
        assertEquals("Union Square", hotelSearch.getSearchString());
        assertFalse(manager.isLongRunningConversation());

        hotelBooking.selectHotel(hotels.get(0));

        Hotel hotel = (Hotel) Contexts.getConversationContext().get("hotel");
        assertEquals("NY", hotel.getCity());
        assertEquals("10011", hotel.getZip());
        assertTrue(manager.isLongRunningConversation());

        hotelBooking.bookHotel();

        Booking booking = (Booking) Contexts.getConversationContext().get("booking");
        assertNotNull(booking.getUser());
        assertNotNull(booking.getHotel());
        assertNull(booking.getCreditCard());
        assertNull(booking.getCreditCardName());

        assertEquals(Contexts.getConversationContext().get("hotel"), booking.getHotel());
        assertEquals(Contexts.getSessionContext().get("user"), booking.getUser());
        assertTrue(manager.isLongRunningConversation());

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
        assertTrue(manager.isLongRunningConversation());

        hotelBooking.confirm();

        bookingList.getBookings();
        List<Booking> bookings = bookingList.getBookingsList();
        assertEquals(1, bookings.size());
        Booking persisted = bookings.get(0);
        assertEquals("NY", persisted.getHotel().getCity());
        assertEquals("gavin", persisted.getUser().getUsername());
        assertFalse(manager.isLongRunningConversation());

        bookingList.setSelectedBooking(persisted);
        bookingList.cancel();

        bookingList.getBookings();
        assertEquals(0, bookingList.getBookingsList().size());
        assertFalse(manager.isLongRunningConversation());
    }
}
