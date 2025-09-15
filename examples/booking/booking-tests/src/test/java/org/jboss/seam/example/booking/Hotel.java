package org.jboss.seam.example.booking;

import java.io.Serializable;
import java.math.BigDecimal;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Hotel entity for the booking application
 */
@Entity
@Table(name = "Hotel")
public class Hotel implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotNull
    @Size(min = 1, max = 50)
    private String name;
    
    @NotNull
    @Size(min = 1, max = 100)
    private String address;
    
    @NotNull
    @Size(min = 1, max = 40)
    private String city;
    
    @NotNull
    @Size(min = 1, max = 6)
    private String state;
    
    @NotNull
    @Size(min = 1, max = 6)
    private String zip;
    
    @NotNull
    @Size(min = 1, max = 40)
    private String country;
    
    @Column(precision = 6, scale = 2)
    private BigDecimal price;
    
    public Hotel() {
    }
    
    public Hotel(String name, String address, String city, String state, String zip, String country) {
        this.name = name;
        this.address = address;
        this.city = city;
        this.state = state;
        this.zip = zip;
        this.country = country;
    }
    
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getAddress() {
        return address;
    }
    
    public void setAddress(String address) {
        this.address = address;
    }
    
    public String getCity() {
        return city;
    }
    
    public void setCity(String city) {
        this.city = city;
    }
    
    public String getState() {
        return state;
    }
    
    public void setState(String state) {
        this.state = state;
    }
    
    public String getZip() {
        return zip;
    }
    
    public void setZip(String zip) {
        this.zip = zip;
    }
    
    public String getCountry() {
        return country;
    }
    
    public void setCountry(String country) {
        this.country = country;
    }
    
    public BigDecimal getPrice() {
        return price;
    }
    
    public void setPrice(BigDecimal price) {
        this.price = price;
    }
    
    @Override
    public String toString() {
        return "Hotel(" + name + "," + address + "," + city + "," + zip + ")";
    }
}
