package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.annotations.Scope;

@Name("outjectionAction")
@Scope(ScopeType.EVENT)
public class OutjectionAction {

    @In(create = true)
    private ProbeDependency probeDependency;

    @Out(required = false, scope = ScopeType.EVENT)
    private String probeOut;

    private String observedSignal = "NONE";

    public String execute(String signal) {
        probeOut = "out-" + signal;
        return probeDependency.value() + ":" + signal;
    }

    @Observer("probe.outjection.signal")
    public void onSignal(String signal) {
        observedSignal = signal;
    }

    public String getObservedSignal() {
        return observedSignal;
    }
}
