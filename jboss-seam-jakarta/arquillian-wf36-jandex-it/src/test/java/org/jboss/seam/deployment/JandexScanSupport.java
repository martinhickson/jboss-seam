package org.jboss.seam.deployment;

import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.Set;

import org.jboss.seam.annotations.Name;

public final class JandexScanSupport {

    private JandexScanSupport() {
    }

    public static boolean hasNameAnnotationOnProbeComponent() throws Exception {
        Set<Class<? extends Annotation>> annotations = new HashSet<Class<? extends Annotation>>();
        annotations.add(Name.class);
        return AbstractScanner.hasAnnotations(
                AbstractScanner.loadClassIndex(
                        "org/jboss/seam/jakarta/it/jandex/ScannedSeamComponent.class",
                        Thread.currentThread().getContextClassLoader()),
                annotations);
    }
}
