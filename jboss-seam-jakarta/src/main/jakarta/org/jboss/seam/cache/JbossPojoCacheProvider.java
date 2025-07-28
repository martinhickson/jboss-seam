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
 * Implementation of CacheProvider backed by JBoss POJO Cache 1.x
 *
 * @author Sebastian Hennebrueder
 * @author Pete Muir
 */

@Name("org.jboss.seam.cache.cacheProvider")
@Scope(APPLICATION)
@BypassInterceptors
@Install(value = false, precedence = BUILT_IN, classDependencies={"org.jboss.cache.pojo.PojoCache", "org.jgroups.MembershipListener", "org.jboss.aop.Dispatcher"})
@AutoCreate
public class JbossPojoCacheProvider extends AbstractJBossCacheProvider<Object>
{

   @Create
   public void create() {
   }

   @Destroy
   public void destroy() {
   }

    @Override
    public Object get(String region, String key) {
        throw new IllegalStateException();
    }


   @Override
   public void put(String region, String key, Object object) {
       throw new IllegalStateException();
   }

   @Override
   public void remove(String region, String key) {
       throw new IllegalStateException();

   }

   @Override
   public Object getDelegate() {
       throw new IllegalStateException();
   }

   @Override
   public void clear() {
       throw new IllegalStateException();
   }
}