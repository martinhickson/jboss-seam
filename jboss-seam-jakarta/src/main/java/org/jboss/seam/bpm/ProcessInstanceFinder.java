package org.jboss.seam.bpm;

import static org.jboss.seam.annotations.Install.BUILT_IN;

import java.util.ArrayList;
import java.util.List;

import org.hibernate.Session;
import org.hibernate.query.criteria.HibernateCriteriaBuilder;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.Install;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Transactional;
import org.jbpm.graph.exe.ProcessInstance;

import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;

/**
 * Support for the process list.
 *
 * @author Gavin King
 */
@Name("org.jboss.seam.bpm.processInstanceFinder")
@Install(precedence = BUILT_IN, dependencies = "org.jboss.seam.bpm.jbpm")
public class ProcessInstanceFinder {

    private String processDefinitionName;
    private String nodeName;
    private Boolean processInstanceEnded = false;
    private Boolean sortDescending = false;

    @Factory(value = "org.jboss.seam.bpm.processInstanceList", autoCreate = true)
    @Transactional
    public List<ProcessInstance> getProcessInstanceList() {
        Session session = ManagedJbpmContext.instance().getSession();

        HibernateCriteriaBuilder cb = session.getCriteriaBuilder();
        CriteriaQuery<ProcessInstance> query = cb.createQuery(ProcessInstance.class);
        Root<ProcessInstance> root = query.from(ProcessInstance.class);
        query.select(root);
        List<Predicate> predicates = new ArrayList<Predicate>();
        if (processInstanceEnded != null) {
            Predicate condition = processInstanceEnded ? cb.isNotNull(root.get("end")) : cb.isNull(root.get("end"));
            predicates.add(condition);
        }
        if (processDefinitionName != null) {
            Join<Object, Object> processDefJoin = root.join("processDefinition");
            predicates.add(cb.equal(processDefJoin.get("name"), processDefinitionName));
        }
        Join<Object, Object> rootTokenJoin = root.join("rootToken");

        if (sortDescending != null) {
            Order order = sortDescending ? cb.desc(rootTokenJoin.get("nodeEnter"))
                    : cb.asc(rootTokenJoin.get("nodeEnter"));
            query.orderBy(order);
        }
        if (nodeName != null) {
            Join<Object, Object> nodeJoin = rootTokenJoin.join("node");
            Predicate nodeNamePredicate = cb.equal(nodeJoin.get("name"), nodeName);
            predicates.add(nodeNamePredicate);
        }
        if (!predicates.isEmpty()) {
            query.where(cb.and(predicates.toArray(new Predicate[0])));
        }
        return session.createQuery(query).getResultList();
    }

    protected String getNodeName() {
        return nodeName;
    }

    protected void setNodeName(String nodeName) {
        this.nodeName = nodeName;
    }

    protected String getProcessDefinitionName() {
        return processDefinitionName;
    }

    protected void setProcessDefinitionName(String processDefinitionName) {
        this.processDefinitionName = processDefinitionName;
    }

    protected Boolean isSortDescending() {
        return sortDescending;
    }

    protected void setSortDescending(Boolean sortDescending) {
        this.sortDescending = sortDescending;
    }

    protected Boolean getProcessInstanceEnded() {
        return processInstanceEnded;
    }

    protected void setProcessInstanceEnded(Boolean ended) {
        this.processInstanceEnded = ended;
    }
}
