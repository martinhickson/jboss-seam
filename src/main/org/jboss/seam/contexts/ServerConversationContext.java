/*
 * JBoss, Home of Professional Open Source  
 * 
 * Distributable under LGPL license. 
 * See terms of license at gnu.org.  
 */
package org.jboss.seam.contexts;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.Seam;
import org.jboss.seam.annotations.PerNestedConversation;
import org.jboss.seam.core.Events;
import org.jboss.seam.core.Manager;

/**
 * A conversation context is a logical context that lasts longer than 
 * a request but shorter than a login session
 * 
 * @author Gavin King
 * @author <a href="mailto:theute@jboss.org">Thomas Heute</a>
 */
public class ServerConversationContext implements Context {

   private final Map<String, Object> session;
   private final Map<String, Object> additions = new HashMap<String, Object>();
   private final Set<String> removals = new HashSet<String>();
   private final String id;
   private final List<String> idStack;
   
   private List<String> getIdStack()
   {
      return idStack==null ? Manager.instance().getCurrentConversationIdStack() : idStack;
   }
   
   private String getId()
   {
      return id==null ? Manager.instance().getCurrentConversationId() : id;
   }
   
   public ScopeType getType()
   {
      return ScopeType.CONVERSATION;
   }

   private String getKey(String name)
   {
      return getPrefix( getId() ) + name;
   }

   private String getKey(String name, String id)
   {
      return getPrefix(id) + name;
   }

   private String getPrefix(String id)
   {
      return ScopeType.CONVERSATION.getPrefix() + '#' + id + '$';
   }

   public ServerConversationContext(Map<String, Object> session)
   {
      this.session = session;
      id = null;
      idStack = null;
   }
      
   public ServerConversationContext(Map<String, Object> session, String id)
   {
      this.session = session;
      this.id = id;
      this.idStack = new LinkedList<String>();
      idStack.add(id);
   }
      
    public Object get(String name) 
    {
      Object result = additions.get(name);
      if (result!=null)
      {
         return unwrapEntityBean(result);
      }
      else
      {
         if ( removals.contains(name) ) 
         {
            return null;
         }
         else
         {
            List<String> stack = getIdStack();
            if (stack==null)
            {
               return unwrapEntityBean( session.get( getKey(name) ) );
            }
            else
            {
               for ( int i=0; i<stack.size(); i++ )
               {
                  String id = stack.get(i);
                  result = session.get( getKey(name, id) );

                  if (result != null) 
                  {
                      return unwrapEntityBean(result);
                  }

                  // only continue checking if it is not pernestedconversation
                  if ( i==0 && isPerNestedConversation(name) ) 
                  {
                      return null;
                  }
               }
               return null;
            }
         }
      }
    }

    private boolean isPerNestedConversation(String name) 
    {
        Component component = Component.forName(name);
        return (component != null) && component.beanClassHasAnnotation(PerNestedConversation.class);
    }

   private Object unwrapEntityBean(Object result)
   {
      if (result==null) return null;
      if ( result instanceof EntityBean )
      {
         return ( (EntityBean) result ).getInstance();
      }
      else
      {
         return result;
      }
   }

   public void set(String name, Object value) 
   {
      if ( Events.exists() ) Events.instance().raiseEvent("org.jboss.seam.preSetVariable." + name);
      if (value==null)
      {
         //yes, we need this
         remove(name);
      }
      else
      {
         removals.remove(name);
         if ( Seam.isEntityClass( value.getClass() ) )
         {
            value = new EntityBean(value);
         }
         additions.put(name, value);
      }
      if ( Events.exists() ) Events.instance().raiseEvent("org.jboss.seam.postSetVariable." + name);
	}

	public boolean isSet(String name) 
   {
		return get(name)!=null;
	}
   
	public void remove(String name) 
   {
      if ( Events.exists() ) Events.instance().raiseEvent("org.jboss.seam.preRemoveVariable." + name);
      additions.remove(name);
      removals.add(name);
      if ( Events.exists() ) Events.instance().raiseEvent("org.jboss.seam.postRemoveVariable." + name);
	}

   public String[] getNames() 
   {
      Set<String> results = getNamesFromSession();
      results.addAll( additions.keySet() ); //after, to override
      return results.toArray(new String[]{});
   }

   private Set<String> getNamesFromSession() 
   {
      HashSet<String> results = new HashSet<String>();
      String prefix = getPrefix( getId() );
      for ( String name: session.keySet() ) 
      {
         if ( name.startsWith(prefix) )
         {
            name = name.substring( prefix.length() );
            if ( !removals.contains(name) ) results.add(name);
         }
      }
      return results;
   }

   public Object get(Class clazz)
   {
      return get( Component.getComponentName(clazz) );
   }
   
   public void clear()
   {
      additions.clear();
      removals.addAll( getNamesFromSession() );
   }
   
   /**
    * Propagate additions and removals to the HttpSession if 
    * the current conversation is long-running, or remove all 
    * attributes if it is a temporary conversation. This work
    * may only be done at the end of the request, since we
    * don't know for sure the conversation id until then.
    */
   public void flush()
   {      
      boolean longRunning = !isCurrent() || Manager.instance().isLongRunningConversation();  
      if ( longRunning )
      {
         //force update for dirty mutable objects
         for ( String name: getNamesFromSession() )
         {
            String key = getKey(name);
            Object attribute = session.get(key);
            if ( attribute!=null && Lifecycle.isAttributeDirty(attribute) )
            {
               session.put(key, attribute);
            }
         }
         //remove removed objects
         for (String name: removals)
         {
            session.remove( getKey(name) );
         }
         removals.clear();
         //add new objects
         for (Map.Entry<String, Object> entry: additions.entrySet())
         {
            session.put( getKey( entry.getKey() ), entry.getValue() );
         }
         additions.clear();
      }
      else
      {
         //TODO: for a pure temporary conversation, this is unnecessary, optimize it
         for ( String name: getNamesFromSession() )
         {
            session.remove( getKey(name) );
         }
      }
   }

   private boolean isCurrent()
   {
      return id==null || id.equals( Manager.instance().getCurrentConversationId() );
   }

   @Override
   public String toString()
   {
      return "ConversationContext(" + getId() + ")";
   }

}
