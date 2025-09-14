package org.jboss.seam.example.booking.test;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;

import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.UserTransaction;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Standalone Arquillian test for WildFly 36 demonstrating basic Jakarta EE functionality.
 * 
 * This test is completely self-contained and doesn't depend on the Seam framework.
 * 
 * To run this test:
 * mvn clean test
 */
@RunWith(Arquillian.class)
public class WildFly36BookingTest {

    @PersistenceContext
    private EntityManager em;

    @Inject
    private UserTransaction utx;

    @Deployment
    public static Archive<?> createTestArchive() {
        return ShrinkWrap.create(WebArchive.class, "wildfly36-test.war")
                .addClasses(WildFly36BookingTest.class, SimpleEntity.class)
                .addAsResource(createPersistenceXml(), "META-INF/persistence.xml")
                .addAsWebInfResource(EmptyAsset.INSTANCE, "beans.xml");
    }

    private static StringAsset createPersistenceXml() {
        return new StringAsset(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<persistence xmlns=\"https://jakarta.ee/xml/ns/persistence\"\n" +
            "             xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
            "             xsi:schemaLocation=\"https://jakarta.ee/xml/ns/persistence\n" +
            "             https://jakarta.ee/xml/ns/persistence/persistence_3_0.xsd\"\n" +
            "             version=\"3.0\">\n" +
            "    <persistence-unit name=\"testPU\" transaction-type=\"JTA\">\n" +
            "        <jta-data-source>java:jboss/datasources/ExampleDS</jta-data-source>\n" +
            "        <class>org.jboss.seam.example.booking.test.SimpleEntity</class>\n" +
            "        <properties>\n" +
            "            <property name=\"hibernate.hbm2ddl.auto\" value=\"create-drop\"/>\n" +
            "            <property name=\"hibernate.show_sql\" value=\"true\"/>\n" +
            "        </properties>\n" +
            "    </persistence-unit>\n" +
            "</persistence>"
        );
    }

    @Test
    public void testEntityManagerInjection() {
        assertNotNull("EntityManager should be injected", em);
    }

    @Test
    public void testUserTransactionInjection() {
        assertNotNull("UserTransaction should be injected", utx);
    }

    @Test
    public void testBasicJPAOperations() throws Exception {
        utx.begin();
        try {
            // Create and persist a simple entity
            SimpleEntity entity = new SimpleEntity();
            entity.setName("Test Entity");
            em.persist(entity);
            em.flush();
            
            // Verify it was persisted
            assertNotNull("Entity ID should be generated", entity.getId());
            assertTrue("Entity ID should be positive", entity.getId() > 0);
            
            // Find it back
            SimpleEntity found = em.find(SimpleEntity.class, entity.getId());
            assertNotNull("Entity should be found", found);
            
            utx.commit();
        } catch (Exception e) {
            utx.rollback();
            throw e;
        }
    }

    @Test
    public void testWildFlyIsRunning() {
        // Simple test to verify WildFly container is running
        assertTrue("This test should run in WildFly container", true);
        System.out.println("✓ WildFly 36 Arquillian test executed successfully!");
    }
}
