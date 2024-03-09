package org.jboss.seam.security;

import java.security.Principal;
import org.apache.cxf.common.security.GroupPrincipal;
import org.apache.cxf.common.security.SimpleGroup;

import javax.security.auth.Subject;

/**
 * Defines a security operation that can be executed within a particular
 * security context.
 *
 * @author Shane Bryzak
 */
public abstract class RunAsOperation
{
   private Principal principal;
   private Subject subject;

   private boolean systemOp = false;

   public RunAsOperation()
   {
      principal = new SimplePrincipal(null);
      subject = new Subject();
   }

   /**
    * A system operation allows any security checks to pass
    *
    * @param systemOp
    */
   public RunAsOperation(boolean systemOp)
   {
      this();
      this.systemOp = systemOp;
   }

   public abstract void execute();

   public Principal getPrincipal()
   {
      return principal;
   }

   public Subject getSubject()
   {
      return subject;
   }

   public RunAsOperation addRole(String role)
   {
      for ( GroupPrincipal sg : getSubject().getPrincipals(GroupPrincipal.class) )
      {
         if ( Identity.ROLES_GROUP.equals( sg.getName() ) )
         {
            sg.addMember(new SimplePrincipal(role));
            break;
         }
      }

      GroupPrincipal roleGroup = new SimpleGroup(Identity.ROLES_GROUP);
      roleGroup.addMember(new SimplePrincipal(role));
      getSubject().getPrincipals().add(roleGroup);

      return this;
   }

   public boolean isSystemOperation()
   {
      return systemOp;
   }

   public void run()
   {
      Identity.instance().runAs(this);
   }
}
