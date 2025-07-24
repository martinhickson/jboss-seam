package org.jboss.seam.jsf;

import java.io.Serializable;

import jakarta.el.MethodExpression;
import jakarta.faces.context.FacesContext;
// Deprecated JSF 1.x EL classes - removed in JSF 4.0
// import jakarta.faces.el.EvaluationException;
// import jakarta.faces.el.MethodBinding;
// import jakarta.faces.el.MethodNotFoundException;

/**
 * Nobody should be using MethodBinding anymore, but if they 
 * are, we need this.
 * 
 * @author Gavin King
 *
 */
@SuppressWarnings("deprecation")
@Deprecated
public class UnifiedELMethodBinding implements Serializable
{
   private transient MethodExpression methodExpression;
   
   private String expressionString;
   private Class[] argTypes;

   public UnifiedELMethodBinding() {}
   
   public UnifiedELMethodBinding(String expressionString, Class[] argTypes)
   {
      this.expressionString = expressionString;
      this.argTypes = argTypes;
   }

   public String getExpressionString()
   {
      return expressionString;
   }

   public Class getType(FacesContext ctx) throws jakarta.el.ELException
   {
      return getMethodExpression(ctx).getMethodInfo( ctx.getELContext() ).getReturnType();
   }

   public Object invoke(FacesContext ctx, Object[] args) throws jakarta.el.ELException
   {
      return getMethodExpression(ctx).invoke( ctx.getELContext(), args);
   }

   @Override
   public String toString()
   {
      return getExpressionString();
   }

   private MethodExpression getMethodExpression(FacesContext ctx)
   {
      if (methodExpression==null)
      {
         // In JSF 1.1 EL (argTypes = null) == (argTypes = new Class[0]), but not in Unified EL
         methodExpression = ctx.getApplication().getExpressionFactory()
                  .createMethodExpression( ctx.getELContext(), expressionString, Object.class, argTypes == null ? new Class[0] : argTypes );
      }
      return methodExpression;
   }
}