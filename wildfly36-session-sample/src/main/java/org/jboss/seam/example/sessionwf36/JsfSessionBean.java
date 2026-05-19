package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;

@Name("jsfSessionBean")
@Scope(ScopeType.SESSION)
public class JsfSessionBean {

    private int hits;

    public int getHits() {
        return hits;
    }

    public void touch() {
        hits++;
    }
}
