package org.jboss.seam.framework;

import java.util.Collection;
import java.util.List;

import org.hibernate.Session;
import org.jboss.seam.annotations.Transactional;
import org.jboss.seam.persistence.QueryParser;

/**
 * A Query object for Hibernate.
 * 
 * @author Gavin King
 *
 */
public class HibernateEntityQuery<E> extends Query<Session, E> {

    private List<E> resultList;
    private E singleResult;
    private Long resultCount;

    private Boolean cacheable;
    private String cacheRegion;
    private Integer fetchSize;

    @Override
    public void validate() {
        super.validate();
        if (getSession() == null) {
            throw new IllegalStateException("hibernateSession is null");
        }
    }

    @Transactional
    @Override
    public List<E> getResultList() {
        if (isAnyParameterDirty()) {
            refresh();
        }
        initResultList();
        return truncResultList(resultList);
    }

    private void initResultList() {
        if (resultList == null) {
            org.hibernate.query.Query<E> query = createQuery();
            resultList = query == null ? null : query.list();
        }
    }

    @Transactional
    @Override
    public boolean isNextExists() {
        return resultList != null && getMaxResults() != null &&
                resultList.size() > getMaxResults();
    }

    @Transactional
    @Override
    public E getSingleResult() {
        if (isAnyParameterDirty()) {
            refresh();
        }
        initSingleResult();
        return singleResult;
    }

    private void initSingleResult() {
        if (singleResult == null) {
            org.hibernate.query.Query<E> query = createQuery();
            singleResult = query == null ? null : query.uniqueResultOptional().orElse(null);
        }
    }

    @Transactional
    @Override
    public Long getResultCount() {
        if (isAnyParameterDirty()) {
            refresh();
        }
        initResultCount();
        return resultCount;
    }

    private void initResultCount() {
        if (resultCount == null) {
            org.hibernate.query.Query<Long> query = createCountQuery();
            resultCount = query == null ? null : query.uniqueResultOptional().orElse(null);
        }
    }

    @Override
    public void refresh() {
        super.refresh();
        resultCount = null;
        resultList = null;
        singleResult = null;
    }

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

    protected org.hibernate.query.Query<E> createQuery() {
        parseEjbql();

        evaluateAllParameters();

        org.hibernate.query.Query<E> query = getSession().createQuery(getRenderedEjbql());
        setParameters(query, getQueryParameterValues(), 0);
        setParameters(query, getRestrictionParameterValues(), getQueryParameterValues().size());
        if (getFirstResult() != null) query.setFirstResult(getFirstResult());
        if (getMaxResults() != null) query.setMaxResults(getMaxResults() + 1); // add one, to detect next page
        if (getCacheable() != null) query.setCacheable(getCacheable());
        if (getCacheRegion() != null) query.setCacheRegion(getCacheRegion());
        if (getFetchSize() != null) query.setFetchSize(getFetchSize());
        return query;
    }

    protected org.hibernate.query.Query<Long> createCountQuery() {
        parseEjbql();

        evaluateAllParameters();

        org.hibernate.query.Query<Long> query = getSession().createQuery(getCountEjbql(), Long.class);
        setParameters(query, getQueryParameterValues(), 0);
        setParameters(query, getRestrictionParameterValues(), getQueryParameterValues().size());
        return query;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private void setParameters(org.hibernate.query.Query<?> query, List<Object> parameters, int start) {
        for (int i = 0; i < parameters.size(); i++) {
            Object parameterValue = parameters.get(i);
            if (isRestrictionParameterSet(parameterValue)) {
                String paramName = QueryParser.getParameterName(start + i);
                if (parameterValue instanceof Collection) {
                    // Hibernate 6 uses setParameter for collections (no setParameterList)
                    query.setParameter(paramName, (Collection) parameterValue);
                } else {
                    query.setParameter(paramName, parameterValue);
                }
            }
        }
    }

    protected Boolean getCacheable() {
        return cacheable;
    }

    protected void setCacheable(Boolean cacheable) {
        this.cacheable = cacheable;
    }

    protected String getCacheRegion() {
        return cacheRegion;
    }

    protected void setCacheRegion(String cacheRegion) {
        this.cacheRegion = cacheRegion;
    }

    protected Integer getFetchSize() {
        return fetchSize;
    }

    protected void setFetchSize(Integer fetchSize) {
        this.fetchSize = fetchSize;
    }
}
