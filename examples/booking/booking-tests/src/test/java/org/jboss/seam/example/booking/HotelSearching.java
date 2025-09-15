package org.jboss.seam.example.booking;

import java.io.Serializable;
import java.math.BigDecimal;
import java.util.List;
import jakarta.ejb.Stateful;
import jakarta.persistence.EntityManager;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.annotations.datamodel.DataModelSelection;

/**
 * Seam component for hotel searching functionality
 */
@Stateful
@Name("hotelSearch")
@Scope(ScopeType.SESSION)
public class HotelSearching implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private EntityManager entityManager;
    
    // Get EntityManager from JNDI-bound EntityManagerFactory (now properly configured in persistence.xml)
    private EntityManager getEntityManager() {
        if (entityManager == null) {
            try {
                System.out.println("[HOTEL-SEARCH-DEBUG] Getting EntityManager from JNDI-bound EMF...");
                javax.naming.InitialContext ctx = new javax.naming.InitialContext();
                
                // First try the direct EntityManager binding
                try {
                    entityManager = (jakarta.persistence.EntityManager) 
                        ctx.lookup("java:/EntityManager/testPU");
                    System.out.println("[HOTEL-SEARCH-DEBUG] Got EntityManager directly from JNDI");
                } catch (javax.naming.NameNotFoundException e) {
                    System.out.println("[HOTEL-SEARCH-DEBUG] Direct EM not in JNDI, trying EMF...");
                    // Fallback to EntityManagerFactory
                    jakarta.persistence.EntityManagerFactory emf = (jakarta.persistence.EntityManagerFactory) 
                        ctx.lookup("java:jboss/EntityManagerFactory/testPU");
                    entityManager = emf.createEntityManager();
                    System.out.println("[HOTEL-SEARCH-DEBUG] Got EntityManager from JNDI-bound EMF");
                }
            } catch (Exception e) {
                System.out.println("[HOTEL-SEARCH-ERROR] Failed to get EntityManager from JNDI: " + e.getMessage());
                throw new RuntimeException("Failed to get EntityManager from JNDI", e);
            }
        }
        return entityManager;
    }
    
    private String searchString;
    private int pageSize = 10;
    private int page;
    
    private List<Hotel> hotels;

    private Hotel selectedHotel;
    
    public void find() {
        System.out.println("[HOTEL-SEARCH-DEBUG] find() method called");
        System.out.println("[HOTEL-SEARCH-DEBUG] Setting page to 0");
        page = 0;
        System.out.println("[HOTEL-SEARCH-DEBUG] About to call queryHotels()");
        queryHotels();
        System.out.println("[HOTEL-SEARCH-DEBUG] find() method completed");
    }
    
    public void nextPage() {
        page++;
        queryHotels();
    }
    
    private void queryHotels() {
        System.out.println("[HOTEL-SEARCH-DEBUG] queryHotels() method called");
        System.out.println("[HOTEL-SEARCH-DEBUG] searchString = " + searchString);
        System.out.println("[HOTEL-SEARCH-DEBUG] page = " + page);
        System.out.println("[HOTEL-SEARCH-DEBUG] pageSize = " + pageSize);
        
        EntityManager em = getEntityManager();
        System.out.println("[HOTEL-SEARCH-DEBUG] EntityManager em = " + em);
        
        if (em == null) {
            System.out.println("[HOTEL-SEARCH-ERROR] EntityManager is NULL!");
            throw new RuntimeException("EntityManager is null in queryHotels()");
        }
        
        String searchPattern = searchString == null ? "%" : '%' + searchString.toLowerCase().replace('*', '%') + '%';
        System.out.println("[HOTEL-SEARCH-DEBUG] searchPattern = " + searchPattern);
        
        try {
            System.out.println("[HOTEL-SEARCH-DEBUG] About to create query...");
            
            jakarta.persistence.TypedQuery<Hotel> query = em.createQuery(
                "select h from Hotel h where lower(h.name) like :pattern " +
                "or lower(h.city) like :pattern " +
                "or lower(h.zip) like :pattern " +
                "or lower(h.address) like :pattern", Hotel.class);
            
            System.out.println("[HOTEL-SEARCH-DEBUG] Query created successfully: " + query);
            
            System.out.println("[HOTEL-SEARCH-DEBUG] Setting parameter 'pattern' to: " + searchPattern);
            query.setParameter("pattern", searchPattern);
            
            System.out.println("[HOTEL-SEARCH-DEBUG] Setting maxResults to: " + pageSize);
            query.setMaxResults(pageSize);
            
            System.out.println("[HOTEL-SEARCH-DEBUG] Setting firstResult to: " + (page * pageSize));
            query.setFirstResult(page * pageSize);
            
            System.out.println("[HOTEL-SEARCH-DEBUG] About to execute query...");
            hotels = query.getResultList();
            
            System.out.println("[HOTEL-SEARCH-DEBUG] Query executed successfully!");
            System.out.println("[HOTEL-SEARCH-DEBUG] hotels = " + hotels);
            System.out.println("[HOTEL-SEARCH-DEBUG] hotels.size() = " + (hotels != null ? hotels.size() : "NULL"));
            
            if (hotels != null && hotels.size() > 0) {
                System.out.println("[HOTEL-SEARCH-DEBUG] First hotel: " + hotels.get(0).getName());
            }
            
        } catch (Exception e) {
            System.out.println("[HOTEL-SEARCH-ERROR] Exception in queryHotels(): " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
        
        System.out.println("[HOTEL-SEARCH-DEBUG] queryHotels() method completed");
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
