//$Id$
package org.jboss.seam.test;

import java.lang.reflect.Method;

import javax.faces.context.FacesContext;

import org.jboss.seam.Component;
import org.jboss.seam.RequiredException;
import org.jboss.seam.Seam;
import org.jboss.seam.annotations.Outcome;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.contexts.Lifecycle;
import org.jboss.seam.core.Manager;
import org.jboss.seam.interceptors.BijectionInterceptor;
import org.jboss.seam.interceptors.ConversationInterceptor;
import org.jboss.seam.interceptors.OutcomeInterceptor;
import org.jboss.seam.interceptors.RemoveInterceptor;
import org.jboss.seam.interceptors.ValidationInterceptor;
import org.jboss.seam.mock.MockFacesContext;
import org.jboss.seam.mock.MockHttpServletRequest;
import org.jboss.seam.mock.MockHttpSession;
import org.jboss.seam.mock.MockServletContext;
import org.testng.annotations.Test;

public class InterceptorTest
{
   
   @Test
   public void testBijectionInterceptor() throws Exception
   {
      MockServletContext servletContext = new MockServletContext();
      MockHttpSession session = new MockHttpSession( servletContext );
      Lifecycle.beginRequest( session );
      Lifecycle.resumeConversation( session, "1" );
      Contexts.getApplicationContext().set( 
               Seam.getComponentName(Manager.class) + ".component", 
               new Component(Manager.class) 
            );
      Contexts.getApplicationContext().set( 
            Seam.getComponentName(Foo.class) + ".component", 
            new Component(Foo.class) 
         );
      
      final Bar bar = new Bar();
      final Foo foo = new Foo();
      Contexts.getSessionContext().set("otherFoo", foo);
      
      BijectionInterceptor bi = new BijectionInterceptor();
      bi.setComponent( new Component(Bar.class) );
      String result = (String) bi.bijectTargetComponent( new MockInvocationContext() {
         @Override
         public Object getBean()
         {
            return bar;
         }

         @Override
         public Object proceed() throws Exception
         {
            assert bar.otherFoo==foo;
            assert bar.foo!=null;
            return bar.foo();
         }
      });
      assert "foo".equals(result);
      assert Contexts.getConversationContext().get("string").equals("out");
      Foo created = bar.foo;
      assert created!=null;
      assert Contexts.getSessionContext().get("foo")==created;
      
      bar.foo=null;
      bar.otherFoo=null;
      bi.bijectTargetComponent( new MockInvocationContext() {
         @Override
         public Object getBean()
         {
            return bar;
         }

         @Override
         public Object proceed() throws Exception
         {
            assert bar.otherFoo==foo;
            assert bar.foo!=null;
            return bar.foo();
         }
      });
      assert bar.foo==created;
      
      try 
      {
         Contexts.getSessionContext().remove("otherFoo");
         bi.bijectTargetComponent( new MockInvocationContext() {
            @Override
            public Object getBean()
            {
               return bar;
            }
            @Override
            public Object proceed() throws Exception
            {
               assert false;
               return null;
            }
         });
         assert false;
      }
      catch (Exception e)
      {
         assert e instanceof RequiredException;
      }
      
      Lifecycle.endApplication(servletContext);
   }
   
   @Test
   public void testConversationInterceptor() throws Exception
   {
      MockServletContext servletContext = new MockServletContext();
      MockHttpSession session = new MockHttpSession( servletContext );
      Lifecycle.beginRequest( session );
      Lifecycle.resumeConversation( session, "1" );
      Contexts.getApplicationContext().set( 
               Seam.getComponentName(Manager.class) + ".component", 
               new Component(Manager.class) 
            );
      
      ConversationInterceptor ci = new ConversationInterceptor();
      ci.setComponent( new Component(Foo.class) );
      
      assert !Manager.instance().isLongRunningConversation();

      String result = (String) ci.endOrBeginLongRunningConversation( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("foo");
         }
         @Override
         public Object proceed() throws Exception
         {
            return "foo";
         }
      });
      
      assert !Manager.instance().isLongRunningConversation();
      assert "foo".equals(result);
      
      result = (String) ci.endOrBeginLongRunningConversation( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("begin");
         }
         @Override
         public Object proceed() throws Exception
         {
            return "begun";
         }
      });
      
      assert Manager.instance().isLongRunningConversation();
      assert "begun".equals(result);

      result = (String) ci.endOrBeginLongRunningConversation( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("foo");
         }
         @Override
         public Object proceed() throws Exception
         {
            return "foo";
         }
      });
      
      assert Manager.instance().isLongRunningConversation();
      assert "foo".equals(result);

      result = (String) ci.endOrBeginLongRunningConversation( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("end");
         }
         @Override
         public Object proceed() throws Exception
         {
            return "ended";
         }
      });
      
      assert !Manager.instance().isLongRunningConversation();
      assert "ended".equals(result);
      
      //TODO: @BeginIf/@EndIf
      Lifecycle.endApplication(servletContext);
   }
   
   @Test
   public void testConversationalConversationInterceptor() throws Exception
   {
      MockServletContext servletContext = new MockServletContext();
      MockHttpSession session = new MockHttpSession( servletContext );
      Lifecycle.beginRequest( session );
      Lifecycle.resumeConversation( session, "1" );
      Contexts.getApplicationContext().set( 
               Seam.getComponentName(Manager.class) + ".component", 
               new Component(Manager.class) 
            );
      
      ConversationInterceptor ci = new ConversationInterceptor();
      ci.setComponent( new Component(Bar.class) );
      
      assert !Manager.instance().isLongRunningConversation();

      String result = (String) ci.endOrBeginLongRunningConversation( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("foo");
         }
         @Override
         public Object proceed() throws Exception
         {
            assert false;
            return null;
         }
      });
      
      assert !Manager.instance().isLongRunningConversation();
      assert "error".equals(result);
      
      result = (String) ci.endOrBeginLongRunningConversation( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("begin");
         }
         @Override
         public Object proceed() throws Exception
         {
            return "begun";
         }
      });
      
      assert Manager.instance().isLongRunningConversation();
      assert "begun".equals(result);

      result = (String) ci.endOrBeginLongRunningConversation( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("foo");
         }
         @Override
         public Object proceed() throws Exception
         {
            return "foo";
         }
      });
      
      assert Manager.instance().isLongRunningConversation();
      assert "foo".equals(result);

      result = (String) ci.endOrBeginLongRunningConversation( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("end");
         }
         @Override
         public Object proceed() throws Exception
         {
            return "ended";
         }
      });
      
      assert !Manager.instance().isLongRunningConversation();
      assert "ended".equals(result);
      
      Lifecycle.endApplication(servletContext);
      
   }
   
   @Test
   public void testValidationInterceptor() throws Exception
   {
      
      new MockFacesContext( new MockHttpServletRequest( new MockHttpSession( new MockServletContext() ) ) ).setCurrent();
      
      ValidationInterceptor vi = new ValidationInterceptor();
      vi.setComponent( new Component(Foo.class) );
      
      final Foo foo = new Foo();
      
      String result = (String) vi.validateTargetComponent( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("foo");
         }
         @Override
         public Object getBean()
         {
            return foo;
         }

         @Override
         public Object proceed() throws Exception
         {
            return foo.foo();
         }
      });
      
      assert "foo".equals(result);
      assert !FacesContext.getCurrentInstance().getMessages().hasNext();      
      
      result = (String) vi.validateTargetComponent( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("bar");
         }
         @Override
         public Object getBean()
         {
            return foo;
         }

         @Override
         public Object proceed() throws Exception
         {
            assert false;
            return foo.bar();
         }
      });
      
      assert "baz".equals(result);
      assert FacesContext.getCurrentInstance().getMessages().hasNext();      

      foo.setValue("not null");
      
      result = (String) vi.validateTargetComponent( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("bar");
         }
         @Override
         public Object getBean()
         {
            return foo;
         }

         @Override
         public Object proceed() throws Exception
         {
            return foo.bar();
         }
      });
      
      assert "bar".equals(result);
   }
   
   @Test
   public void testOutcomeInterceptor() throws Exception
   {
      OutcomeInterceptor oi = new OutcomeInterceptor();
      
      String outcome = (String) oi.interceptOutcome( new MockInvocationContext() {
         @Override
         public Object proceed() throws Exception
         {
            return Outcome.REDISPLAY;
         } 
      } );
      assert outcome==null;
      
      outcome = (String) oi.interceptOutcome( new MockInvocationContext() {
         @Override
         public Object proceed() throws Exception
         {
            return "success";
         } 
      } );
      assert outcome=="success";
      
      Object result = oi.interceptOutcome( new MockInvocationContext() {
         @Override
         public Object proceed() throws Exception
         {
            return InterceptorTest.this;
         } 
      } );
      assert result==this;
   }
   
   @Test 
   public void testRemoveInterceptor() throws Exception
   {
      MockServletContext servletContext = new MockServletContext();
      Lifecycle.beginRequest( new MockHttpSession( servletContext ) );
      Contexts.getSessionContext().set( "foo", new Foo() );
      
      RemoveInterceptor ri = new RemoveInterceptor();
      ri.setComponent( new Component(Foo.class) );
      
      ri.removeIfNecessary( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("foo");
         }
      } );
      
      assert Contexts.getSessionContext().isSet("foo");
      
      ri.removeIfNecessary( new MockInvocationContext() {
         @Override
         public Method getMethod()
         {
            return InterceptorTest.getMethod("destroy");
         }
      } );
      
      assert !Contexts.getSessionContext().isSet("foo");
      
      Lifecycle.endApplication(servletContext);
   }

   static Method getMethod(String name)
   {
      try
      {
         return Foo.class.getMethod(name);
      }
      catch (Exception e)
      {
         assert false;
         return null;
      }
   }
}
