package org.jboss.seam.jakarta.it.jandex;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Named;

@Named("jsfPageOne")
@RequestScoped
public class JsfPageOneBean {

    public String getHeading() {
        return "JSF Page One";
    }
}
