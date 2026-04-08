package org.jboss.seam.jakarta.it.jandex;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Named;
import org.jboss.seam.deployment.JandexScanSupport;

@Named("jsfPageTwo")
@RequestScoped
public class JsfPageTwoBean {

    public String getHeading() {
        return "JSF Page Two";
    }

    public String getScanResult() {
        try {
            boolean found = JandexScanSupport.hasNameAnnotationOnProbeComponent();
            return found ? "FOUND" : "MISSING";
        } catch (Exception e) {
            return "ERROR";
        }
    }
}
