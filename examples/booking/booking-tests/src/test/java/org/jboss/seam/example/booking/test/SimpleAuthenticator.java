package org.jboss.seam.example.booking.test;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.PersistenceContext;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.example.booking.User;
import org.jboss.seam.log.Log;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;

/**
 * Simple authenticator for testing Seam security
 */
@Name("authenticator")
public class SimpleAuthenticator {
    
    @Logger
    private Log log;
    
    @PersistenceContext
    private EntityManager entityManager;
    
    @In
    private Identity identity;
    
    @In
    private Credentials credentials;
    
    public boolean authenticate() {
        log.info("Authenticating user: #0", credentials.getUsername());
        
        try {
            User user = entityManager.createQuery(
                "select u from User u where u.username = :username and u.password = :password", 
                User.class)
                .setParameter("username", credentials.getUsername())
                .setParameter("password", credentials.getPassword())
                .getSingleResult();
            
            if (user != null) {
                identity.addRole("user");
                log.info("Authentication successful for user: #0", credentials.getUsername());
                return true;
            }
        } catch (NoResultException e) {
            log.info("Authentication failed for user: #0", credentials.getUsername());
        }
        
        return false;
    }
}
