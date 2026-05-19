package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;

@Name("probeDependency")
@Scope(ScopeType.EVENT)
public class ProbeDependency {

    public String value() {
        return "dep-ok";
    }
}
