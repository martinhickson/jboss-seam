package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Scope;

@Name("sessionEventsState")
@Scope(ScopeType.SESSION)
public class SessionEventsState {

    @In(create = true)
    private ProbeDependency probeDependency;

    private int sessionHits;
    private String lastSignal = "NONE";

    public int incrementAndGet() {
        sessionHits++;
        return sessionHits;
    }

    @Observer("probe.scopes.signal")
    public void onSignal(String signal) {
        lastSignal = signal;
    }

    public String getDependencyValue() {
        return probeDependency != null ? probeDependency.value() : "MISSING";
    }

    public String getLastSignal() {
        return lastSignal;
    }
}
