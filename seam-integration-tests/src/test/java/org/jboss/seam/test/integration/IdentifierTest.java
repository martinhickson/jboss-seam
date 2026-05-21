package org.jboss.seam.test.integration;

import jakarta.persistence.EntityManager;

import org.hibernate.Session;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OverProtocol;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.seam.framework.EntityIdentifier;
import org.jboss.seam.framework.HibernateEntityIdentifier;
import org.jboss.seam.mock.JUnitSeamTest;
import org.jboss.shrinkwrap.api.Archive;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * @author Pete Muir
 *
 */
@RunWith(Arquillian.class)
public class IdentifierTest extends JUnitSeamTest
{
	@Deployment(name="IdentifierTest")
	@OverProtocol("Servlet 5.0") 
	public static Archive<?> createDeployment()
	{
		return Deployments.defaultSeamDeployment(IdentifierTest.class, Country.class, CountryHome.class);
	}

    @Test
    public void testEntityIdentifier() throws Exception
    {
        new ComponentTest()
        {

            @Override
            protected void testComponents() throws Exception
            {
                setValue("#{countryHome.instance.name}", "foo");
                invokeMethod("#{countryHome.persist}");
                Country country = (Country) getValue("#{countryHome.instance}");
                EntityManager entityManager = (EntityManager) getValue("#{countryHome.entityManager}");
                
                EntityIdentifier entityIdentifier = new EntityIdentifier(country, entityManager);
                assert "foo".equals(((Country) entityIdentifier.find(entityManager)).getName());
                EntityIdentifier entityIdentifier2 = new EntityIdentifier(country, entityManager);
                assert entityIdentifier.equals(entityIdentifier2);
            }
            
        }.run();
    }
    
    @Test
    @org.junit.Ignore("HibernatePersistenceProvider not configured in Jakarta mock deployment (JPA-only)")
    public void testHibernateEntityIdentifier() throws Exception
    {
        new ComponentTest()
        {

            @Override
            protected void testComponents() throws Exception
            {
                setValue("#{countryHome.instance.name}", "foo");
                invokeMethod("#{countryHome.persist}");
                Country country = (Country) getValue("#{countryHome.instance}");
                Session session =  (Session) getValue("#{countryHome.entityManager.delegate}");
                
                HibernateEntityIdentifier hibernateEntityIdentifier = new HibernateEntityIdentifier(country, session);
                assert "foo".equals(((Country) hibernateEntityIdentifier.find(session)).getName());
                HibernateEntityIdentifier hibernateEntityIdentifier2 = new HibernateEntityIdentifier(country, session);
                assert hibernateEntityIdentifier.equals(hibernateEntityIdentifier2);
            }
            
        }.run();
    }
    
}
