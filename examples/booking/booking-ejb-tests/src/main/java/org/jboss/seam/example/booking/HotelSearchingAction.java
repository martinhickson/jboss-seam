package org.jboss.seam.example.booking;

import java.util.ArrayList;
import java.util.List;

import jakarta.ejb.Stateless;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.annotations.security.Restrict;

@Stateless
@Name("hotelSearch")
@Scope(ScopeType.SESSION)
@Restrict("#{identity.loggedIn}")
public class HotelSearchingAction implements HotelSearching {

    @PersistenceContext(unitName = "bookingDatabase")
    private EntityManager em;

    private String searchString;
    private int pageSize = 10;
    private int page;
    private boolean nextPageAvailable;

    @DataModel
    private List<Hotel> hotels;

    public void find() {
        page = 0;
        queryHotels();
    }

    public void nextPage() {
        page++;
        queryHotels();
    }

    private void queryHotels() {
        String pattern = searchString == null
                ? "%"
                : '%' + searchString.toLowerCase().replace('*', '%') + '%';
        List<Hotel> results = em.createQuery(
                        "select h from Hotel h where lower(h.name) like :pattern "
                                + "or lower(h.city) like :pattern or lower(h.zip) like :pattern "
                                + "or lower(h.address) like :pattern",
                        Hotel.class)
                .setParameter("pattern", pattern)
                .setMaxResults(pageSize + 1)
                .setFirstResult(page * pageSize)
                .getResultList();

        nextPageAvailable = results.size() > pageSize;
        if (nextPageAvailable) {
            hotels = new ArrayList<>(results.subList(0, pageSize));
        } else {
            hotels = results;
        }
    }

    public boolean isNextPageAvailable() {
        return nextPageAvailable;
    }

    public int getPageSize() {
        return pageSize;
    }

    public void setPageSize(int pageSize) {
        this.pageSize = pageSize;
    }

    @Factory(value = "pattern", scope = ScopeType.EVENT)
    public String getSearchPattern() {
        return searchString == null
                ? "%"
                : '%' + searchString.toLowerCase().replace('*', '%') + '%';
    }

    public String getSearchString() {
        return searchString;
    }

    public void setSearchString(String searchString) {
        this.searchString = searchString;
    }

    public void destroy() {
    }
}
