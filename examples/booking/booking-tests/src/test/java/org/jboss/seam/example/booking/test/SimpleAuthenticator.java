package org.jboss.seam.example.booking.test;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import static org.jboss.seam.ScopeType.SESSION;

import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.annotations.Transactional;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.example.booking.User;
import org.jboss.seam.log.Log;
import org.jboss.seam.security.Credentials;
import org.jboss.seam.security.Identity;

/**
 * Simple authenticator for testing Seam security in the WAR-only deployment.
 */
@Name("authenticator")
@Transactional
public class SimpleAuthenticator {

    @Logger
    private Log log;

    @In
    private EntityManager entityManager;

    @In
    private Identity identity;

    @In
    private Credentials credentials;

    @In(required = false)
    @Out(required = false, scope = SESSION)
    private User user;

    public boolean authenticate() {
        log.info("Authenticating user: #0", credentials.getUsername());

        if (Contexts.isSessionContextActive()) {
            Object pending = Contexts.getSessionContext().get(HotelOidcServlet.OIDC_SUBJECT);
            if (pending instanceof String && pending.equals(credentials.getUsername())) {
                Contexts.getSessionContext().remove(HotelOidcServlet.OIDC_SUBJECT);
                this.user = userForOidc((String) pending);
                identity.addRole("user");
                log.info("Accepted identity provider subject: #0", pending);
                return true;
            }
        }

        try {
            User user = entityManager.createQuery(
                            "select u from User u where u.username = :username and u.password = :password",
                            User.class)
                    .setParameter("username", credentials.getUsername())
                    .setParameter("password", credentials.getPassword())
                    .getSingleResult();

            this.user = user;
            identity.addRole("user");
            log.info("Authentication successful for user: #0", credentials.getUsername());
            return true;
        } catch (NoResultException e) {
            log.info("Authentication failed for user: #0", credentials.getUsername());
        }

        return false;
    }

    private User userForOidc(String username) {
        try {
            return entityManager.createQuery(
                            "select u from User u where u.username = :username", User.class)
                    .setParameter("username", username)
                    .getSingleResult();
        } catch (NoResultException e) {
            User created = new User(username, Long.toHexString(System.nanoTime()), username);
            entityManager.persist(created);
            return created;
        }
    }
}
