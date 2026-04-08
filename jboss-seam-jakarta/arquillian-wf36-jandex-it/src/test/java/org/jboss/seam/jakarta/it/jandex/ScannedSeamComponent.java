package org.jboss.seam.jakarta.it.jandex;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;

@Name("jandexProbe")
@Scope(ScopeType.EVENT)
public class ScannedSeamComponent {
    public String value() {
        return "jandex-scan-ok";
    }
}
