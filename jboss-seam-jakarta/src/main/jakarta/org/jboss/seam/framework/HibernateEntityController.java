package org.jboss.seam.framework;

import java.io.Serializable;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;

import org.hibernate.Filter;
import org.hibernate.HibernateException;
import org.hibernate.LockOptions;
import org.hibernate.Session;
import org.hibernate.query.Query;

/**
 * Base class for controller objects that perform
 * persistence operations using Hibernate. Adds
 * convenience methods for access to the Hibernate
 * Session object.
 * 
 * @author Gavin King
 *
 */
public class HibernateEntityController extends PersistenceController<Session> {

    public Session getSession() {
        return getPersistenceContext();
    }

    public void setSession(Session session) {
        setPersistenceContext(session);
    }

    @Override
    protected String getPersistenceContextName() {
        return "hibernateSession";
    }

    // Deprecated createCriteria replaced by JPA Criteria API - example helper
    protected <T> CriteriaQuery<T> createCriteria(Class<T> clazz) {
        CriteriaBuilder cb = getSession().getCriteriaBuilder();
        CriteriaQuery<T> criteriaQuery = cb.createQuery(clazz);
        Root<T> root = criteriaQuery.from(clazz);
        criteriaQuery.select(root);
        return criteriaQuery;
    }

    protected Query<?> createQuery(String hql) throws HibernateException {
        return getSession().createQuery(hql);
    }

    protected void delete(Object entity) throws HibernateException {
        getSession().delete(entity);
    }

    protected Filter enableFilter(String name) {
        return getSession().enableFilter(name);
    }

    protected void flush() throws HibernateException {
        getSession().flush();
    }

    protected <T> T get(Class<T> clazz, Serializable id, LockOptions lockOptions) throws HibernateException {
        return getSession().get(clazz, id, lockOptions);
    }

    protected <T> T get(Class<T> clazz, Serializable id) throws HibernateException {
        return getSession().get(clazz, id);
    }

    protected Query<?> getNamedQuery(String name) throws HibernateException {
        return getSession().getNamedQuery(name);
    }

    protected <T> T load(Class<T> clazz, Serializable id, LockOptions lockOptions) throws HibernateException {
        return getSession().load(clazz, id, lockOptions);
    }

    protected <T> T load(Class<T> clazz, Serializable id) throws HibernateException {
        return getSession().load(clazz, id);
    }

    protected void lock(Object entity, LockOptions lockOptions) throws HibernateException {
        getSession().buildLockRequest(lockOptions).lock(entity);
    }

    protected <T> T merge(T entity) throws HibernateException {
        return getSession().merge(entity);
    }

    protected void persist(Object entity) throws HibernateException {
        getSession().persist(entity);
    }

    protected void refresh(Object entity, LockOptions lockOptions) throws HibernateException {
        getSession().buildLockRequest(lockOptions).lock(entity);
        getSession().refresh(entity);
    }

    protected void refresh(Object entity) throws HibernateException {
        getSession().refresh(entity);
    }
}
