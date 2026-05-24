package org.jboss.seam.example.booking;

import java.io.Serializable;
import java.math.BigDecimal;
import java.text.DateFormat;
import java.util.Date;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.jboss.seam.annotations.Name;

/**
 * Booking entity for the booking application
 */
@Entity
@Table(name = "Booking")
@Name("booking")
public class Booking implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne
    @JoinColumn(name = "userId")
    private User user;
    
    @ManyToOne
    @JoinColumn(name = "hotelId")
    private Hotel hotel;
    
    @NotNull
    @Temporal(TemporalType.DATE)
    private Date checkinDate;
    
    @NotNull
    @Temporal(TemporalType.DATE)
    private Date checkoutDate;
    
    @Size(min = 1, max = 50)
    @Pattern(regexp = "^\\d*$", message = "Credit card number must be numeric")
    private String creditCard;
    
    @Size(min = 1, max = 70)
    private String creditCardName;

    private int creditCardExpiryMonth;

    private int creditCardExpiryYear;

    private int beds;
    
    private boolean smoking;
    
    @Column(precision = 6, scale = 2)
    private BigDecimal total;
    
    public Booking() {
    }
    
    public Booking(Hotel hotel, User user) {
        this.hotel = hotel;
        this.user = user;
    }
    
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public User getUser() {
        return user;
    }
    
    public void setUser(User user) {
        this.user = user;
    }
    
    public Hotel getHotel() {
        return hotel;
    }
    
    public void setHotel(Hotel hotel) {
        this.hotel = hotel;
    }
    
    public Date getCheckinDate() {
        return checkinDate;
    }
    
    public void setCheckinDate(Date checkinDate) {
        this.checkinDate = checkinDate;
    }
    
    public Date getCheckoutDate() {
        return checkoutDate;
    }
    
    public void setCheckoutDate(Date checkoutDate) {
        this.checkoutDate = checkoutDate;
    }
    
    public String getCreditCard() {
        return creditCard;
    }
    
    public void setCreditCard(String creditCard) {
        this.creditCard = creditCard;
    }
    
    public String getCreditCardName() {
        return creditCardName;
    }
    
    public void setCreditCardName(String creditCardName) {
        this.creditCardName = creditCardName;
    }

    public int getCreditCardExpiryMonth() {
        return creditCardExpiryMonth;
    }

    public void setCreditCardExpiryMonth(int creditCardExpiryMonth) {
        this.creditCardExpiryMonth = creditCardExpiryMonth;
    }

    public int getCreditCardExpiryYear() {
        return creditCardExpiryYear;
    }

    public void setCreditCardExpiryYear(int creditCardExpiryYear) {
        this.creditCardExpiryYear = creditCardExpiryYear;
    }

    public int getBeds() {
        return beds;
    }
    
    public void setBeds(int beds) {
        this.beds = beds;
    }
    
    public boolean isSmoking() {
        return smoking;
    }
    
    public void setSmoking(boolean smoking) {
        this.smoking = smoking;
    }
    
    public BigDecimal getTotal() {
        return total;
    }
    
    public void setTotal(BigDecimal total) {
        this.total = total;
    }
    
    public String getDescription() {
        DateFormat df = DateFormat.getDateInstance(DateFormat.MEDIUM);
        return hotel == null ? null : hotel.getName() + 
               ", " + df.format(getCheckinDate()) + 
               " to " + df.format(getCheckoutDate());
    }
    
    @Override
    public String toString() {
        return "Booking(" + user + "," + hotel + ")";
    }
}
