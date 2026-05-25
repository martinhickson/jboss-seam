package org.jboss.seam.example.booking;

import jakarta.ejb.Local;

@Local
public interface HotelSearching {
    void find();
    void nextPage();
    boolean isNextPageAvailable();
    int getPageSize();
    void setPageSize(int pageSize);
    String getSearchString();
    void setSearchString(String searchString);
    void destroy();
}
