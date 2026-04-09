package org.jboss.seam.jakarta.it.jandex;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.annotations.Scope;

@Name("phaseFourAction")
@Scope(ScopeType.EVENT)
public class PhaseFourAction {

    @In(create = true)
    private PhaseOneDependency phaseOneDependency;

    @Out(required = false, scope = ScopeType.EVENT)
    private String phaseFourOut;

    private String observedSignal = "NONE";

    public String execute(String signal) {
        phaseFourOut = "out-" + signal;
        return phaseOneDependency.value() + ":" + signal;
    }

    @Observer("phase4.signal")
    public void onSignal(String signal) {
        observedSignal = signal;
    }

    public String getObservedSignal() {
        return observedSignal;
    }
}
