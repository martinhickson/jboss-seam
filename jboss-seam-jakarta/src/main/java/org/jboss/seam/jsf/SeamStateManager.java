package org.jboss.seam.jsf;

import java.io.IOException;

import jakarta.faces.application.StateManager;
import jakarta.faces.context.FacesContext;

/**
 * Custom JSF StateManager that integrates with Seam's conversation and page context.
 */
public class SeamStateManager extends StateManager {

    private final StateManager delegate;

    public SeamStateManager(StateManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public void writeState(FacesContext context, Object state) throws IOException {
        delegate.writeState(context, state);
    }

    @Override
    public boolean isSavingStateInClient(FacesContext context) {
        return delegate.isSavingStateInClient(context);
    }
}
