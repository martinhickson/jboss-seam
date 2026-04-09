package org.jboss.seam.jakarta.it.jandex;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Scope;

@Name("phaseTwoConversationState")
@Scope(ScopeType.CONVERSATION)
public class PhaseTwoConversationState {

    @In(create = true)
    private PhaseOneDependency phaseOneDependency;

    private int counter = 0;
    private String lastSignal = "NONE";

    public void markStep() {
        counter++;
    }

    @Observer("phase2.signal")
    public void onSignal(String signal) {
        lastSignal = signal;
    }

    public int getCounter() {
        return counter;
    }

    public String getLastSignal() {
        return lastSignal;
    }

    public String getDependencyValue() {
        return phaseOneDependency != null ? phaseOneDependency.value() : "MISSING";
    }
}
