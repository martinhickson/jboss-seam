package org.jboss.seam.persistence;

import static org.jboss.seam.annotations.Install.FRAMEWORK;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collection;
import java.util.Map;

import jakarta.persistence.EntityManager;
import jakarta.transaction.Synchronization;
import jakarta.persistence.metamodel.IdentifiableType;
import jakarta.persistence.metamodel.Metamodel;

import org.hibernate.Session;
import org.hibernate.Hibernate;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.StaleStateException;
import org.hibernate.TransientObjectException;
import org.jboss.seam.Component;
import org.jboss.seam.Entity;
import org.jboss.seam.Entity.NotEntityException;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.FlushModeType;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.intercept.BypassInterceptors;
import org.jboss.seam.core.Expressions.ValueExpression;
import org.jboss.seam.log.Log;
import org.jboss.seam.log.Logging;

/**
 * Updated for Hibernate 6: uses JPA Metamodel API instead of deprecated ClassMetadata.
 */
@Name("org.jboss.seam.persistence.persistenceProvider")
@Scope(ScopeType.STATELESS)
@BypassInterceptors
@Install(precedence = FRAMEWORK, classDependencies = {"org.hibernate.Session", "javax.persistence.EntityManager"})
public class HibernatePersistenceProvider extends PersistenceProvider {

    private static final Log log = Logging.getLog(HibernatePersistenceProvider.class);

    private static Class<?> FULL_TEXT_SESSION_PROXY_CLASS;
    private static Method FULL_TEXT_SESSION_CONSTRUCTOR;
    private static Class<?> FULL_TEXT_ENTITYMANAGER_PROXY_CLASS;
    private static Method FULL_TEXT_ENTITYMANAGER_CONSTRUCTOR;

    static {
        boolean hibernateSearchPresent = false;
        try {
            Class.forName("org.hibernate.search.Version");
            hibernateSearchPresent = true;
        } catch (Exception e) {
            log.debug("Hibernate Search not present", e);
        }
        if (hibernateSearchPresent) {
            try {
                Class<?> searchClass = Class.forName("org.hibernate.search.Search");
                try {
                    FULL_TEXT_SESSION_CONSTRUCTOR = searchClass.getDeclaredMethod("getFullTextSession", Session.class);
                } catch (NoSuchMethodException e) {
                    log.debug("Search.getFullTextSession not found, trying deprecated name");
                    FULL_TEXT_SESSION_CONSTRUCTOR = searchClass.getDeclaredMethod("createFullTextSession", Session.class);
                }
                FULL_TEXT_SESSION_PROXY_CLASS = Class.forName("org.jboss.seam.persistence.FullTextHibernateSessionProxy");
                Class<?> jpaSearchClass = Class.forName("org.hibernate.search.jpa.Search");
                try {
                    FULL_TEXT_ENTITYMANAGER_CONSTRUCTOR = jpaSearchClass.getDeclaredMethod("getFullTextEntityManager", EntityManager.class);
                } catch (NoSuchMethodException e) {
                    log.debug("Search.getFullTextEntityManager not found, trying deprecated name");
                    FULL_TEXT_ENTITYMANAGER_CONSTRUCTOR = jpaSearchClass.getDeclaredMethod("createFullTextEntityManager", EntityManager.class);
                }
                FULL_TEXT_ENTITYMANAGER_PROXY_CLASS = Class.forName("org.jboss.seam.persistence.FullTextEntityManagerProxy");
                log.debug("Hibernate Search available");
            } catch (Exception e) {
                log.debug("Unable to load Hibernate Search", e);
            }
        }
    }

    public HibernatePersistenceProvider() {
        super.init();
        featureSet.add(Feature.WILDCARD_AS_COUNT_QUERY_SUBJECT);
    }

    static Session proxySession(Session session) {
        if (FULL_TEXT_SESSION_PROXY_CLASS == null) {
            if (session instanceof HibernateSessionProxy) {
                return session;
            }
            return (Session) Proxy.newProxyInstance(
                    Thread.currentThread().getContextClassLoader(),
                    new Class[]{HibernateSessionProxy.class},
                    new HibernateSessionInvocationHandler(session)
            );
        } else {
            try {
                if (FULL_TEXT_SESSION_PROXY_CLASS.isAssignableFrom(session.getClass())) {
                    return session;
                }
                Session ftSession = (Session) FULL_TEXT_SESSION_CONSTRUCTOR.invoke(null, session);
                return (Session) Proxy.newProxyInstance(
                        Thread.currentThread().getContextClassLoader(),
                        new Class[]{FULL_TEXT_SESSION_PROXY_CLASS},
                        new HibernateSessionInvocationHandler(ftSession)
                );
            } catch (Exception e) {
                log.warn("Could not wrap into FullTextSessionProxy; using regular", e);
                return (session instanceof HibernateSessionProxy)
                        ? session
                        : (Session) Proxy.newProxyInstance(
                            Thread.currentThread().getContextClassLoader(),
                            new Class[]{HibernateSessionProxy.class},
                            new HibernateSessionInvocationHandler(session));
            }
        }
    }

    @Override
    public Object proxyDelegate(Object delegate) {
        try {
            return proxySession((Session) delegate);
        } catch (NotHibernateException nhe) {
            return super.proxyDelegate(delegate);
        } catch (Exception e) {
            throw new RuntimeException("Could not proxy delegate", e);
        }
    }

    @Override
    public void setFlushModeManual(EntityManager em) {
        try {
            getSession(em).setHibernateFlushMode(org.hibernate.FlushMode.MANUAL);
        } catch (NotHibernateException nhe) {
            super.setFlushModeManual(em);
        }
    }

    @Override
    public boolean isDirty(EntityManager em) {
        try {
            return getSession(em).isDirty();
        } catch (NotHibernateException nhe) {
            return super.isDirty(em);
        }
    }

    @Override
    public Object getId(Object bean, EntityManager em) {
        try {
            return getSession(em).getIdentifier(bean);
        } catch (NotHibernateException nhe) {
            return super.getId(bean, em);
        } catch (TransientObjectException e) {
            if (bean instanceof HibernateProxy) {
                Object impl = ((HibernateProxy) bean).getHibernateLazyInitializer().getImplementation();
                return super.getId(impl, em);
            }
            return super.getId(bean, em);
        }
    }

    @Override
    public Object getVersion(Object bean, EntityManager em) {
        try {
            return getVersionViaMetamodel(bean, em);
        } catch (NotHibernateException nhe) {
            return super.getVersion(bean, em);
        }
    }

    @Override
    public void checkVersion(Object bean, EntityManager em, Object oldVersion, Object version) {
        try {
            Object currentVersion = getVersionViaMetamodel(bean, em);
            if (currentVersion == null || !currentVersion.equals(version)) {
                throw new StaleStateException("Version mismatch (perhaps passivated state?)");
            }
        } catch (NotHibernateException nhe) {
            super.checkVersion(bean, em, oldVersion, version);
        }
    }

    @Override
    public void enableFilter(org.jboss.seam.persistence.Filter f, EntityManager em) {
        try {
            org.hibernate.Filter filter = getSession(em).enableFilter(f.getName());
            for (Map.Entry<String, ValueExpression> entry : f.getParameters().entrySet()) {
                Object val = entry.getValue().getValue();
                if (val instanceof Collection) {
                    filter.setParameterList(entry.getKey(), (Collection<?>) val);
                } else {
                    filter.setParameter(entry.getKey(), val);
                }
            }
            filter.validate();
        } catch (NotHibernateException nhe) {
            super.enableFilter(f, em);
        }
    }

    @Override
    public boolean registerSynchronization(Synchronization sync, EntityManager em) {
        try {
            getSession(em).getTransaction().registerSynchronization(sync);
            return true;
        } catch (NotHibernateException nhe) {
            return super.registerSynchronization(sync, em);
        }
    }

    @Override
    public String getName(Object bean, EntityManager em) {
        try {
            return getSession(em).getEntityName(bean);
        } catch (Exception e) {
            return super.getName(bean, em);
        }
    }

    @Override
    public EntityManager proxyEntityManager(EntityManager em) {
        if (FULL_TEXT_ENTITYMANAGER_PROXY_CLASS == null) {
            return super.proxyEntityManager(em);
        }
        try {
            EntityManager ftEm = (EntityManager) FULL_TEXT_ENTITYMANAGER_CONSTRUCTOR.invoke(null, super.proxyEntityManager(em));
            return (EntityManager) Proxy.newProxyInstance(
                    Thread.currentThread().getContextClassLoader(),
                    new Class[]{FULL_TEXT_ENTITYMANAGER_PROXY_CLASS},
                    new EntityManagerInvocationHandler(ftEm)
            );
        } catch (Exception e) {
            return super.proxyEntityManager(em);
        }
    }

    private Object getVersionViaMetamodel(Object bean, EntityManager em) {
        Metamodel mm = em.getEntityManagerFactory().getMetamodel();
        Class<?> beanClass = getEntityClass(bean);
        @SuppressWarnings("unchecked")
        IdentifiableType<Object> ident = (IdentifiableType<Object>) mm.entity(beanClass);
        if (ident.hasVersionAttribute()) {
            try {
                Method getter = beanClass.getMethod("get" +
                        Character.toUpperCase(ident.getAttribute("version").getName().charAt(0)) +
                        ident.getAttribute("version").getName().substring(1));
                return getter.invoke(bean);
            } catch (Exception ex) {
                throw new RuntimeException("Could not access version property", ex);
            }
        }
        return null;
    }

    @Override
    public Class<?> getBeanClass(Object bean) {
        return getEntityClass(bean);
    }

    public static Class<?> getEntityClass(Object bean) {
        Class<?> clazz = null;
        try {
            clazz = Entity.forBean(bean).getBeanClass();
        } catch (NotEntityException e) {
            // fallback next
        }
        if (clazz == null) {
            clazz = Hibernate.getClass(bean);
        }
        return clazz != null ? clazz : bean.getClass();
    }

    private Session getSession(EntityManager em) {
        Object del = em.getDelegate();
        if (del instanceof Session) {
            return (Session) del;
        }
        throw new NotHibernateException();
    }

    static class NotHibernateException extends IllegalArgumentException {}

    public static HibernatePersistenceProvider instance() {
        return (HibernatePersistenceProvider) Component.getInstance(HibernatePersistenceProvider.class, ScopeType.STATELESS);
    }
}
