package org.jboss.seam.example.booking;

import static org.jboss.seam.ScopeType.SESSION;

import java.util.List;

import jakarta.ejb.Stateless;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Out;

@Stateless
@Name("authenticator")
public class AuthenticatorAction implements Authenticator {

    @PersistenceContext(unitName = "bookingDatabase")
    private EntityManager em;

    @In(required = false)
    @Out(required = false, scope = SESSION)
    private User user;

    @SuppressWarnings("unchecked")
    public boolean authenticate() {
        List<User> results = em.createQuery(
                        "select u from User u where u.username=#{identity.username} and u.password=#{identity.password}",
                        User.class)
                .getResultList();
        if (results.isEmpty()) {
            return false;
        }
        user = results.get(0);
        return true;
    }
}
