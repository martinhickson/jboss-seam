package org.jboss.seam.mock;

import java.io.IOException;

import javax.faces.context.FacesContext;
import javax.faces.render.ResponseStateManager;

@SuppressWarnings("deprecation")
public class MockResponseStateManager extends ResponseStateManager
{

   public Object getComponentStateToRestore(FacesContext ctx)
   {
      return new Object();
   }

   public Object getTreeStructureToRestore(FacesContext ctx, String x)
   {
      return new Object();
   }

   @Override
   public void writeState(FacesContext ctx, Object viewState) throws IOException
   {

   }

   @Override
   public boolean isPostback(FacesContext context)
   {
      return context.getExternalContext().getRequestParameterMap().containsKey(ResponseStateManager.VIEW_STATE_PARAM);
   }

}
