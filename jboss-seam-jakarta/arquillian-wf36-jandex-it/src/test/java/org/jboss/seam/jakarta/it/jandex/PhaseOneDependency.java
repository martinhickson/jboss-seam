package org.jboss.seam.jakarta.it.jandex;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;

@Name("phaseOneDependency")
@Scope(ScopeType.EVENT)
public class PhaseOneDependency {

    public String value() {
        return "dep-ok";
    }
}
