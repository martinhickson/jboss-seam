package org.jboss.seam.example.booking.test;

import org.jboss.shrinkwrap.api.spec.WebArchive;

/**
 * WildFly 36 test deployment using Jakarta Seam artifacts.
 */
public final class Deployments {

    private Deployments() {
    }

    public static WebArchive bookingDeployment() throws Exception {
        return BookingWildFly36Deployment.create();
    }
}
