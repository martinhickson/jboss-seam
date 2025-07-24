package org.jboss.seam.bpm;

import static org.jboss.seam.ScopeType.APPLICATION;
import static org.jboss.seam.annotations.Install.BUILT_IN;

import java.util.ArrayList;
import java.util.List;

import org.hibernate.Session;
import org.hibernate.query.criteria.HibernateCriteriaBuilder;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Transactional;
import org.jboss.seam.annotations.Unwrap;
import org.jbpm.taskmgmt.exe.TaskInstance;

import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;

/**
 * Support for a task list ordered by priority.
 *
 * @see TaskInstanceList
 * @see PooledTask
 * @author Gavin King
 */
@Name("org.jboss.seam.bpm.taskInstancePriorityList")
@Scope(APPLICATION)
@Install(precedence = BUILT_IN, dependencies = "org.jboss.seam.bpm.jbpm")
public class TaskInstancePriorityList {

    // TODO: we really need to cache the list in the event context,
    // but then we would need some events to refresh it
    // when tasks end, which is non-trivial to do....

    @Unwrap
    @Transactional
    public List<TaskInstance> getTaskInstanceList() {
        return getTaskInstanceList(Actor.instance().getId());
    }

    private List<TaskInstance> getTaskInstanceList(String actorId) {
        if (actorId == null) return null;

        Session session = ManagedJbpmContext.instance().getSession();
        HibernateCriteriaBuilder cb = session.getCriteriaBuilder();
        CriteriaQuery<TaskInstance> query = cb.createQuery(TaskInstance.class);
        Root<TaskInstance> root = query.from(TaskInstance.class);

        List<Predicate> predicates = new ArrayList<>();
        predicates.add(cb.equal(root.get("actorId"), actorId));
        predicates.add(cb.isTrue(root.get("isOpen")));
        predicates.add(cb.isFalse(root.get("isSuspended")));

        query.select(root)
             .where(cb.and(predicates.toArray(new Predicate[0])))
             .orderBy(cb.asc(root.get("priority")));

        return session.createQuery(query)
                      .setCacheable(true)
                      .getResultList();
    }
}
