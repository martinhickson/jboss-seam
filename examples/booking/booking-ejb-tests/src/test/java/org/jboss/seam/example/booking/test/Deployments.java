package org.jboss.seam.example.booking.test;

import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;

public final class Deployments {

    private Deployments() {
    }

    public static EnterpriseArchive bookingEarDeployment(Class<?>... testClasses) throws Exception {
        String earName = "seam-booking-ejb-" + testClasses[0].getSimpleName().toLowerCase() + ".ear";
        return BookingEarWildFly36Deployment.create(earName, testClasses);
    }
}
