package org.jboss.seam.jakarta.it.jandex;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Scope;

@Name("phaseThreeSessionState")
@Scope(ScopeType.SESSION)
public class PhaseThreeSessionState {

    @In(create = true)
    private PhaseOneDependency phaseOneDependency;

    private int sessionHits;
    private String lastSignal = "NONE";

    public int incrementAndGet() {
        sessionHits++;
        return sessionHits;
    }

    @Observer("phase3.signal")
    public void onSignal(String signal) {
        lastSignal = signal;
    }

    public String getDependencyValue() {
        return phaseOneDependency != null ? phaseOneDependency.value() : "MISSING";
    }

    public String getLastSignal() {
        return lastSignal;
    }
}
