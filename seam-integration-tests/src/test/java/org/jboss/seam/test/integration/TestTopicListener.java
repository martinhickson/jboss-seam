package org.jboss.seam.test.integration;

import jakarta.ejb.ActivationConfigProperty;
import jakarta.ejb.MessageDriven;
import jakarta.jms.Message;
import jakarta.jms.MessageListener;
import jakarta.jms.TextMessage;

import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.test.integration.MessagingTest.SimpleReference;

@MessageDriven(activationConfig =
{
      @ActivationConfigProperty(propertyName = "destinationType", propertyValue = "jakarta.jms.Topic"),
      @ActivationConfigProperty(propertyName = "destination", propertyValue = "topic/seamTest")
})
@Name("testTopicListener")
public class TestTopicListener implements MessageListener
{
   @In
   private SimpleReference<String> testMessage;

   public void onMessage(Message msg)
   {
      try
      {
         testMessage.setValue(((TextMessage) msg).getText());
      }
      catch (Exception e)
      {
         e.printStackTrace();
      }
   }
}