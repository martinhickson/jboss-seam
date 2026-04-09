package org.jboss.seam.jakarta.it.jandex;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Scope;

@Name("phaseOneAction")
@Scope(ScopeType.CONVERSATION)
public class PhaseOneAction {

    @In(create = true)
    private PhaseOneDependency phaseOneDependency;

    private String lastObserved = "NONE";

    public String readDependency() {
        return phaseOneDependency != null ? phaseOneDependency.value() : "MISSING";
    }

    @Observer("phase1.event")
    public void onPhaseOneEvent(String payload) {
        lastObserved = payload;
    }

    public String getLastObserved() {
        return lastObserved;
    }
}
