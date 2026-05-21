package org.jboss.seam.test.integration.mock;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.seam.mock.JUnitSeamTest;
import org.jboss.seam.test.integration.Action;
import org.jboss.seam.test.integration.Deployments;
import org.jboss.seam.test.integration.Person;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(Arquillian.class)
public class SeamTestTest extends JUnitSeamTest
{
   @Deployment
   public static Archive<?> createDeployment() {
      return Deployments.defaultSeamDeployment(SeamTestTest.class, Action.class, Person.class, Action.class, Person.class);
   }

   private static final String PETER_NAME = "Pete Muir";
   private static final String PETER_USERNAME = "pmuir";
   
   @Test
   public void testEl() throws Exception
   {
      new ComponentTest()
      {
         @Override
         protected void testComponents() throws Exception
         {
            setValue("#{person.name}", PETER_NAME);
            assert PETER_NAME.equals(getValue("#{person.name}"));
            assert "success".equals(invokeMethod("#{action.go}"));
         }
      }.run();
   }
   
   @Test
   public void testSeamSecurity() throws Exception
   {
      new FacesRequest("/index.xhtml")
      {

         @Override
         protected void updateModelValues() throws Exception
         {
            setValue("#{identity.username}", PETER_USERNAME);
         }
         
         @Override
         protected void renderResponse() throws Exception
         {
            assert getValue("#{identity.username}").equals(PETER_USERNAME);
         }
      }.run();
   }

}
