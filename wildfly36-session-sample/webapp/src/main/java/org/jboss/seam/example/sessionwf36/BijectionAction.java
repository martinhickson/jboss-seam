package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Scope;

@Name("bijectionAction")
@Scope(ScopeType.EVENT)
public class BijectionAction {

    @In(create = true)
    private ProbeDependency probeDependency;

    private String lastObserved = "NONE";

    public String readDependency() {
        return probeDependency != null ? probeDependency.value() : "MISSING";
    }

    @Observer("probe.bijection.event")
    public void onBijectionEvent(String payload) {
        lastObserved = payload;
    }

    public String getLastObserved() {
        return lastObserved;
    }
}
