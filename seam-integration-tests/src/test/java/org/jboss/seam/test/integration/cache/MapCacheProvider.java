package org.jboss.seam.test.integration.cache;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.cache.CacheProvider;

/**
 * Minimal in-memory {@link CacheProvider} for Seam UI integration tests.
 */
@Name("org.jboss.seam.cache.cacheProvider")
@Scope(ScopeType.APPLICATION)
@BypassInterceptors
public class MapCacheProvider extends CacheProvider<Map<String, Map<String, Object>>>
{
   private final Map<String, Map<String, Object>> store = new ConcurrentHashMap<>();

   @Override
   public Map<String, Map<String, Object>> getDelegate()
   {
      return store;
   }

   @Override
   public Object get(String region, String key)
   {
      return regionStore(region).get(key);
   }

   @Override
   public void put(String region, String key, Object object)
   {
      regionStore(region).put(key, object);
   }

   @Override
   public void remove(String region, String key)
   {
      regionStore(region).remove(key);
   }

   @Override
   public void clear()
   {
      store.clear();
   }

   private Map<String, Object> regionStore(String region)
   {
      String regionName = region != null ? region : getDefaultRegion();
      return store.computeIfAbsent(regionName, ignored -> new ConcurrentHashMap<>());
   }
}
