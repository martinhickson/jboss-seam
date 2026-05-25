package org.jboss.seam.example.booking.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.util.Map;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * HTTP JSF POST booking flow against the EAR deployment (@Stateful EJB backend).
 */
@RunWith(Arquillian.class)
public class BookingEjbJsfPostIT {

    @Deployment(testable = false)
    public static EnterpriseArchive deployment() throws Exception {
        return BookingEarWildFly36Deployment.create("seam-booking-ejb-jsf.ear");
    }

    @ArquillianResource
    private URL baseUrl;

    @Test
    @RunAsClient
    public void bookHotelJsfPostThroughEarDeployment() throws Exception {
        BookingHttpTestClient probeClient = new BookingHttpTestClient(baseUrl);
        probeClient.installCookieManager();
        try {
            probeClient.getText(probeClient.url("home.seam"));
            Map<String, String> login = probeClient.getProbeLogin("gavin", "foobar");
            assertTrue("Login failed: " + login, "loggedIn".equals(login.get("LOGIN_RESULT")));

            JsfFormClient jsf = new JsfFormClient(baseUrl);
            jsf.setCookieHeader(cookieHeaderFromManager());

            JsfFormClient.JsfFormPage main = jsf.get("main.seam");
            assertTrue("Expected hotel search on main.seam: " + snippet(main.body),
                    main.body.contains("Search Hotels"));

            JsfFormClient.JsfFormPage searchForm = JsfFormClient.parseForm(main.body, "searchCriteria");
            Map<String, String> searchPost = jsf.buildPostFields(searchForm, Map.of(
                    "searchCriteria:searchString", "Union Square",
                    "searchCriteria:pageSize", "5",
                    "searchCriteria:findHotels", "Find Hotels"));
            JsfFormClient.JsfFormPage searchResults = jsf.postForm("main.seam", searchPost);
            assertTrue("Expected search results: " + snippet(searchResults.body),
                    searchResults.body.contains("selectHotel"));

            String viewHotelHref = JsfFormClient.findSelectHotelLink(searchResults.body);
            assertNotNull("selectHotel link not found in search results", viewHotelHref);

            JsfFormClient.JsfFormPage hotel = jsf.get(viewHotelHref);
            assertTrue("Expected hotel page: " + snippet(hotel.body),
                    hotel.body.contains("View Hotel") && hotel.body.contains("Book Hotel"));
            assertTrue("Expected conversation id on hotel page: " + hotel.finalUrl,
                    hotel.finalUrl.contains("scid=") || hotel.finalUrl.contains("cid="));

            JsfFormClient.JsfFormPage hotelForm = JsfFormClient.parseForm(hotel.body, "hotel");
            Map<String, String> bookPost = jsf.buildPostFields(hotelForm, Map.of(
                    "hotel:bookHotel", "Book Hotel"));
            String hotelResource = hotel.finalUrl.contains("hotel.seam") ? hotel.finalUrl : "hotel.seam";
            JsfFormClient.JsfFormPage bookPage = jsf.postForm(hotelResource, bookPost);

            assertTrue("Book Hotel POST should reach booking form, got: " + bookPage.finalUrl
                            + " body: " + snippet(bookPage.body),
                    bookPage.finalUrl.contains("book.seam")
                            || (bookPage.body.contains("Book Hotel")
                                    && bookPage.body.contains("Check In Date")));
        } finally {
            probeClient.clearCookieManager();
        }
    }

    private static String cookieHeaderFromManager() {
        java.net.CookieManager manager = (java.net.CookieManager) java.net.CookieHandler.getDefault();
        if (manager == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (java.net.HttpCookie cookie : manager.getCookieStore().getCookies()) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append(cookie.getName()).append('=').append(cookie.getValue());
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    private static String snippet(String body) {
        return body.length() > 300 ? body.substring(0, 300) + "..." : body;
    }
}
