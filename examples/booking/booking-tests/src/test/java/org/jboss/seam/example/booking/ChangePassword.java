package org.jboss.seam.example.booking;

import jakarta.ejb.Local;

@Local
public interface ChangePassword {
    void changePassword();
    boolean isChanged();
    String getVerify();
    void setVerify(String verify);
    void destroy();
}
