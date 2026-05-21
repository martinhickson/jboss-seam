package org.jboss.seam.example.booking.test;

import static org.jboss.seam.ScopeType.EVENT;

import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Transactional;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.example.booking.User;

import jakarta.persistence.EntityManager;
import jakarta.persistence.FlushModeType;

/**
 * Event-scoped change-password component for the test WAR (no EJB).
 */
@Name("changePassword")
@Scope(EVENT)
@Transactional
public class SimpleChangePassword {

    @In
    private EntityManager entityManager;

    private String verify;
    private boolean changed;

    public String getVerify() {
        return verify;
    }

    public void setVerify(String verify) {
        this.verify = verify;
    }

    /** Invoked from password.xhtml via EL. */
    public void changePassword() {
        User sessionUser = (User) Contexts.getSessionContext().get("user");
        if (sessionUser == null) {
            throw new IllegalStateException("No user in session");
        }
        changePassword(sessionUser.getPassword(), verify);
    }

    /**
     * @param newPassword desired password from the UI
     * @param verify      confirmation field
     */
    public void changePassword(String newPassword, String verify) {
        changed = false;
        User user = (User) Contexts.getSessionContext().get("user");
        if (user == null) {
            throw new IllegalStateException("No user in session");
        }

        FlushModeType previousFlushMode = entityManager.getFlushMode();
        entityManager.setFlushMode(FlushModeType.COMMIT);
        try {
            String username = user.getUsername();
            String storedPassword = entityManager
                    .createQuery("select u.password from User u where u.username = :username", String.class)
                    .setParameter("username", username)
                    .getSingleResult();

            if (newPassword.equals(verify)) {
                int updated = entityManager.createQuery(
                                "update User u set u.password = :password where u.username = :username")
                        .setParameter("password", newPassword)
                        .setParameter("username", username)
                        .executeUpdate();
                if (updated != 1) {
                    throw new IllegalStateException(
                            "Expected to update one user, updated " + updated + " for " + username);
                }
                entityManager.flush();
                entityManager.clear();
                user = entityManager.find(User.class, username);
                changed = true;
            } else {
                user = new User(user.getName(), storedPassword, username);
            }
            Contexts.getSessionContext().set("user", user);
        } finally {
            entityManager.setFlushMode(previousFlushMode);
        }
    }

    public boolean isChanged() {
        return changed;
    }

    public void destroy() {
    }
}
