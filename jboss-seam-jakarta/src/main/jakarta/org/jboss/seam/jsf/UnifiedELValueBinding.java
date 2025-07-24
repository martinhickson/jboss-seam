package org.jboss.seam.jsf;

import java.io.Serializable;

import jakarta.el.ValueExpression;
import jakarta.faces.context.FacesContext;
// Deprecated JSF 1.x EL classes - removed in JSF 4.0
// import jakarta.faces.el.EvaluationException;
// import jakarta.faces.el.PropertyNotFoundException;
// import jakarta.faces.el.ValueBinding;

/**
 * Nobody should be using ValueBinding anymore, but if they 
 * are, we need this.
 * 
 * @author Gavin King
 *
 */
@SuppressWarnings("deprecation")
@Deprecated
public class UnifiedELValueBinding implements Serializable
{
   private transient ValueExpression valueExpression;
   
   private String expressionString;

   public UnifiedELValueBinding(String expressionString)
   {
      this.expressionString = expressionString;
   }

   public UnifiedELValueBinding() {}
   
   public String getExpressionString()
   {
      return expressionString;
   }

   public Class getType(FacesContext ctx) throws jakarta.el.ELException {
      return getValueExpression(ctx).getType( ctx.getELContext() );
   }

   public Object getValue(FacesContext ctx) throws jakarta.el.ELException {
   	return getValueExpression(ctx).getValue( ctx.getELContext() );
   }

   public boolean isReadOnly(FacesContext ctx) throws jakarta.el.ELException {
   	return getValueExpression(ctx).isReadOnly( ctx.getELContext() );
   }

   public void setValue(FacesContext ctx, Object value) throws jakarta.el.ELException {
      getValueExpression(ctx).setValue( ctx.getELContext(), value);
   }
   
   @Override
   public String toString()
   {
      return getExpressionString();
   }

   private ValueExpression getValueExpression(FacesContext ctx)
   {
      if (valueExpression==null)
      {
         valueExpression = ctx.getApplication().getExpressionFactory()
                  .createValueExpression( ctx.getELContext(), expressionString, Object.class );
      }
      return valueExpression;
   }
}