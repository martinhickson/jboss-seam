package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.core.Manager;

@Name("conversationJsfBean")
@Scope(ScopeType.CONVERSATION)
public class ConversationJsfBean {

    private int steps;

    public void touch() {
        Manager manager = Manager.instance();
        if (!manager.isLongRunningConversation()) {
            manager.beginConversation();
        }
        steps++;
    }

    public int getSteps() {
        return steps;
    }

    public String getConversationId() {
        return Manager.instance().getCurrentConversationId();
    }
}
