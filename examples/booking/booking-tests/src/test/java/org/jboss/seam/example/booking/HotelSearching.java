package org.jboss.seam.example.booking;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.List;
import jakarta.ejb.Stateful;
import jakarta.persistence.EntityManager;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Create;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Transactional;
import org.jboss.seam.annotations.datamodel.DataModel;

/**
 * Seam component for hotel searching functionality
 */
@Stateful
@Name("hotelSearch")
@Scope(ScopeType.SESSION)
@Transactional
public class HotelSearching implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @In
    private EntityManager entityManager;
    
    public HotelSearching() {
    }
    
    @Create
    public void create() {
        // Component initialization
    }
    
    private String searchString;
    private int pageSize = 10;
    private int page;
    
    @DataModel
    private List<Hotel> hotels;

    private Hotel selectedHotel;
    
    public void find() {
        page = 0;
        queryHotels();
    }
    
    public void nextPage() {
        page++;
        queryHotels();
    }
    
    private void queryHotels() {
        String searchPattern = searchString == null ? "%" : '%' + searchString.toLowerCase().replace('*', '%') + '%';
        
        try {
            jakarta.persistence.TypedQuery<Hotel> query = entityManager.createQuery(
                "select h from Hotel h where lower(h.name) like :pattern " +
                "or lower(h.city) like :pattern " +
                "or lower(h.zip) like :pattern " +
                "or lower(h.address) like :pattern", Hotel.class);
            
            query.setParameter("pattern", searchPattern);
            query.setMaxResults(pageSize);
            query.setFirstResult(page * pageSize);
            
            hotels = query.getResultList();
            
        } catch (Exception e) {
            throw new RuntimeException("Exception in queryHotels()", e);
        }
    }
    
    public boolean isNextPageAvailable() {
        return hotels != null && hotels.size() == pageSize;
    }
    
    public int getPageSize() {
        return pageSize;
    }
    
    public void setPageSize(int pageSize) {
        this.pageSize = pageSize;
    }
    
    public String getSearchString() {
        return searchString;
    }
    
    public void setSearchString(String searchString) {
        this.searchString = searchString;
    }
    
    public List<Hotel> getHotels() {
        return hotels;
    }
    
    public Hotel getSelectedHotel() {
        return selectedHotel;
    }
    
    public void setSelectedHotel(Hotel selectedHotel) {
        this.selectedHotel = selectedHotel;
    }
    
    // Initialize some test data
    public void initializeTestData() {
        // Create test hotel data
        Hotel hotel = new Hotel("W New York - Union Square", "201 Park Avenue South", "NY", "NY", "10011", "USA");
        hotel.setPrice(new BigDecimal("401.00"));
        entityManager.persist(hotel);
        entityManager.flush();
    }
}
