package org.jboss.seam.test.integration;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OverProtocol;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.seam.Component;
import org.jboss.seam.core.Events;
import org.jboss.seam.core.Manager;
import org.jboss.seam.mock.JUnitSeamTest;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;


/**
 * 
 * @author Pete Muir
 *
 */
@RunWith(Arquillian.class)
public class EventTest extends JUnitSeamTest {

	@Deployment(name="IdentifierTest")
	@OverProtocol("Servlet 5.0")
	public static Archive<?> createDeployment()
	{
		return Deployments.defaultSeamDeployment(EventTest.class, BeanA.class, BeanB.class);
	}
	
    @Test
    public void testEventChain() throws Exception {

        new FacesRequest("/index.xhtml") {
            @Override
            protected void invokeApplication() throws Exception {
                assert "Foo".equals(getValue("#{beanA.myValue}"));
                assert getValue("#{beanB.myValue}") == null;
                Events.instance().raiseEvent("BeanA.refreshMyValue");
                assert "Bar".equals(getValue("#{beanA.myValue}"));
            }

            @Override
            protected void renderResponse() throws Exception {
                assert "Bar".equals(getValue("#{beanB.myValue}"));
            }
        }.run();
    }

}


