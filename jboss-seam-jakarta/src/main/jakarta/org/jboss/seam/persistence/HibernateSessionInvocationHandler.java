package org.jboss.seam.persistence;

import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.hibernate.Session;
import org.hibernate.query.Query;
import org.hibernate.query.NativeQuery;

public class HibernateSessionInvocationHandler implements InvocationHandler, Serializable {

    private static final long serialVersionUID = 4954720887288965536L;

    private final Session delegate;

    public HibernateSessionInvocationHandler(Session delegate) {
        this.delegate = delegate;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        try {
            if ("createQuery".equals(method.getName())
                    && args != null && args.length > 0
                    && args[0] instanceof String) {
                return handleCreateQueryWithString(method, args);
            }

            if ("createNativeQuery".equals(method.getName())
                    && args != null && args.length > 0
                    && args[0] instanceof String) {
                return handleCreateNativeQuery(method, args);
            }

            return method.invoke(delegate, args);
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    /**
     * Handles EL interpolation in HQL queries.
     */
    protected Object handleCreateQueryWithString(Method method, Object[] args) throws Throwable {
        if (args[0] == null) {
            return method.invoke(delegate, args);
        }

        String hql = (String) args[0];

        if (hql.contains("#")) {
            QueryParser qp = new QueryParser(hql);
            Object[] newArgs = args.clone();
            newArgs[0] = qp.getEjbql();
            Query<?> query = (Query<?>) method.invoke(delegate, newArgs);
            for (int i = 0; i < qp.getParameterValueBindings().size(); i++) {
                query.setParameter(
                        QueryParser.getParameterName(i),
                        qp.getParameterValueBindings().get(i).getValue()
                );
            }
            return query;
        } else {
            return method.invoke(delegate, args);
        }
    }

    /**
     * Handles EL interpolation for native SQL queries if needed.
     */
    protected Object handleCreateNativeQuery(Method method, Object[] args) throws Throwable {
        if (args[0] == null) {
            return method.invoke(delegate, args);
        }

        String sql = (String) args[0];

        if (sql.contains("#")) {
            QueryParser qp = new QueryParser(sql);
            Object[] newArgs = args.clone();
            newArgs[0] = qp.getEjbql();
            NativeQuery<?> query = (NativeQuery<?>) method.invoke(delegate, newArgs);
            for (int i = 0; i < qp.getParameterValueBindings().size(); i++) {
                query.setParameter(
                        QueryParser.getParameterName(i),
                        qp.getParameterValueBindings().get(i).getValue()
                );
            }
            return query;
        } else {
            return method.invoke(delegate, args);
        }
    }

}
