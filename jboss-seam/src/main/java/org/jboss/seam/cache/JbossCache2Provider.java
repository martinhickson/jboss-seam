package org.jboss.seam.cache;

import static org.jboss.seam.ScopeType.APPLICATION;
import static org.jboss.seam.annotations.Install.BUILT_IN;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Create;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.intercept.BypassInterceptors;

/**
 * Implementation of CacheProvider backed by JBoss Cache 2.x. for simple
 * objects.
 *
 * @author Sebastian Hennebrueder
 * @author Pete Muir
 */

@Name("org.jboss.seam.cache.cacheProvider")
@Scope(APPLICATION)
@BypassInterceptors
@Install(value = false, precedence = BUILT_IN, classDependencies = {"org.jboss.cache.Cache", "org.jgroups.MembershipListener"})
@AutoCreate
public class JbossCache2Provider
    extends AbstractJBossCacheProvider<Object>
{

    @Create
    public void create() {
        throw new UnsupportedOperationException();
    }

    @Destroy
    public void destroy() {
    }

    @Override
    public Object get(String region, String key) {
        return null;
    }

    @Override
    public void put(String region, String key, Object object) {
    }

    @Override
    public void remove(String region, String key) {
    }

    @Override
    public void clear() {
    }

    @Override
    public Object getDelegate() {
        return null;
    }

}