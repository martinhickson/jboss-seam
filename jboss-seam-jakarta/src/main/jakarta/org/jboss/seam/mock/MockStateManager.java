package org.jboss.seam.mock;

import java.io.IOException;

import jakarta.faces.application.StateManager;
import jakarta.faces.context.FacesContext;

public class MockStateManager extends StateManager {

    @Override
    public void writeState(FacesContext context, Object state) throws IOException {
        super.writeState(context, state);
    }

    @Override
    public boolean isSavingStateInClient(FacesContext context) {
        return super.isSavingStateInClient(context);
    }

    @Override
    public String getViewState(FacesContext context) {
        return super.getViewState(context);
    }
}
