package org.jboss.seam.jsf;

import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.navigation.Pages;

import jakarta.faces.component.UIViewRoot;
import jakarta.faces.context.FacesContext;
import jakarta.faces.view.StateManagementStrategy;

/**
 * A wrapper for the JSF implementation's StateManager that allows
 * us to intercept saving of the serialized component tree. This
 * is quite ugly but was needed in order to allow conversations to
 * be started and manipulated during the RENDER_RESPONSE phase.
 *
 * @author Gavin King
 */
public class SeamStateManagementStrategy extends StateManagementStrategy
{
   private final SeamStateManagementStrategy stateManager;

   public SeamStateManagementStrategy(SeamStateManagementStrategy sm)
   {
      this.stateManager = sm;
   }

   @Override
   public UIViewRoot restoreView(FacesContext ctx, String str1, String str2)
   {
      return stateManager.restoreView(ctx, str1, str2);
   }

   @Override
   public Object saveView(FacesContext facesContext)
   {

      if ( Contexts.isPageContextActive() )
      {
         //store the page parameters in the view root
         Pages.instance().updateStringValuesInPageContextUsingModel(facesContext);
      }

      return stateManager.saveView(facesContext);
   }
}