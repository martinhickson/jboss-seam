package org.jboss.seam.example.booking;

import java.io.Serializable;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
/**
 * User entity for the booking application
 */
@Entity
@Table(name = "Customer")
public class User implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @Id
    @Size(min = 1, max = 100)
    private String username;
    
    @NotNull
    @Size(min = 1, max = 100)
    private String password;
    
    @NotNull
    @Size(min = 1, max = 100)
    private String name;
    
    public User() {
    }
    
    public User(String name, String password, String username) {
        this.name = name;
        this.password = password;
        this.username = username;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    @Override
    public String toString() {
        return "User(" + username + ")";
    }
}
