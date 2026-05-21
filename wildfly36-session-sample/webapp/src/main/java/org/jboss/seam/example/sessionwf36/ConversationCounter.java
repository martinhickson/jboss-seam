package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Scope;

@Name("conversationCounter")
@Scope(ScopeType.CONVERSATION)
public class ConversationCounter {

    @In(create = true)
    private ProbeDependency probeDependency;

    private int steps;
    private String lastSignal = "NONE";

    public void markStep() {
        steps++;
    }

    @Observer("probe.conversation.signal")
    public void onSignal(String signal) {
        lastSignal = signal;
    }

    public int getSteps() {
        return steps;
    }

    public String getLastSignal() {
        return lastSignal;
    }

    public String getDependencyValue() {
        return probeDependency != null ? probeDependency.value() : "MISSING";
    }
}
