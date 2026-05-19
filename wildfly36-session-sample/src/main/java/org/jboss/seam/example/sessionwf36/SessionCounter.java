package org.jboss.seam.example.sessionwf36;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;

@Name("sessionCounter")
@Scope(ScopeType.SESSION)
public class SessionCounter {

    private int hits;

    public int incrementAndGet() {
        hits++;
        return hits;
    }

    public int getHits() {
        return hits;
    }
}
