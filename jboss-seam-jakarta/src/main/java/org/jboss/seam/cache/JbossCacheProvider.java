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
 * Implementation of CacheProvider backed by JBoss Cache 1.x
 *
 * @author Sebastian Hennebrueder
 * @author Pete Muir
 */

@Name("org.jboss.seam.cache.cacheProvider")
@Scope(APPLICATION)
@BypassInterceptors
@Install(precedence = BUILT_IN, classDependencies={"org.jboss.cache.TreeCache", "org.jgroups.MembershipListener"})
@AutoCreate
public class JbossCacheProvider extends AbstractJBossCacheProvider<Object> {

   @Create
   public void create() {
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
   public Object getDelegate() {
      return null;
   }

   @Override
   public void clear() {
   }
}