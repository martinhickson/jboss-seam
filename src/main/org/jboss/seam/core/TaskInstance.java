/*
 * JBoss, Home of Professional Open Source
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.jboss.seam.core;

import static org.jboss.seam.InterceptionType.NEVER;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Intercept;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Unwrap;
import org.jbpm.db.JbpmSession;

/**
 * @author Gavin King
 * @version $Revision$
 */
@Scope(ScopeType.APPLICATION)
@Name("taskInstance")
@Intercept(NEVER)
public class TaskInstance 
{
   
   @Unwrap
   public org.jbpm.taskmgmt.exe.TaskInstance getTaskInstance()
   {
      Long taskId = Process.instance().getTaskId();
      if (taskId!=null)
      {
         //TODO: should we cache this lookup?
         JbpmSession session = (JbpmSession) Component.getInstance( ManagedJbpmSession.class, true );
         return session.getTaskMgmtSession().loadTaskInstance(taskId);
      }
      else
      {
         return null;
      }
   }
   
   public static org.jbpm.taskmgmt.exe.TaskInstance instance()
   {
      return (org.jbpm.taskmgmt.exe.TaskInstance) Component.getInstance(TaskInstance.class, true);
   }
   
}
