package org.jboss.seam.jakarta.it.jandex;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;

@Name("phaseThreeApplicationState")
@Scope(ScopeType.APPLICATION)
public class PhaseThreeApplicationState {

    private int totalHits;

    public int incrementAndGet() {
        totalHits++;
        return totalHits;
    }
}
