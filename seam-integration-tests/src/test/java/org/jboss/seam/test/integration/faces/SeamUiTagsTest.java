package org.jboss.seam.test.integration.faces;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.OverProtocol;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.seam.test.integration.Deployments;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jbpm.taskmgmt.exe.TaskInstance;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

/**
 * Smoke and render tests for every {@code s:} tag in {@code META-INF/s.taglib.xml}.
 * Conversation/button/link propagation behaviour is covered by
 * {@link ConversationPropagationsTest} and {@link ViewUrlBuilderTest}.
 */
@RunWith(Arquillian.class)
@RunAsClient
public class SeamUiTagsTest
{
   private final WebClient client = new WebClient();

   public SeamUiTagsTest()
   {
      client.setJavaScriptEnabled(false);
   }

   @ArquillianResource
   URL contextPath;

   @Deployment(name = "SeamUiTagsTest")
   @OverProtocol("Servlet 5.0")
   public static Archive<?> createDeployment()
   {
      WebArchive war = Deployments.realSeamDeployment(SeamUiTagsTest.class, SeamUiTagsBean.class);
      return war.addClasses(org.jboss.seam.test.integration.Country.class)
            .addAsLibrary(Deployments.jarFor(TaskInstance.class))
            .addAsWebResource("seam-ui-tags.xhtml", "seam-ui-tags.xhtml")
            .addAsWebResource("seam-ui-resource.xhtml", "seam-ui-resource.xhtml");
   }

   @Test
   public void pageLoadsWithAllTagSections() throws Exception
   {
      HtmlPage page = client.getPage(contextPath + "seam-ui-tags.seam");
      assertEquals("Seam UI Tags", page.getTitleText());
      assertBasicTags(page);
      assertFormTags(page);
      assertMediaTags(page);
      assertCommandTags(page);
      assertConverterTags(page);
   }

   private static void assertBasicTags(HtmlPage page)
   {
      assertTrue(page.getElementById("tag-span").getAttribute("class").contains("tag-span"));
      assertTrue(page.getElementById("tag-div").getAttribute("class").contains("tag-div"));
      assertTrue(page.getBody().getTextContent().contains("cached-content"));
      assertTrue(page.getBody().getTextContent().contains("Formatted"));
      assertTrue(page.getBody().getTextContent().contains("Seam"));
      assertNotNull(page.getElementById("fragment-inner"));
   }

   private static void assertFormTags(HtmlPage page)
   {
      String html = page.asXml();
      assertTrue(html.contains("nameInput"));
      assertTrue(html.contains("colorMenu"));
      assertTrue(html.contains("itemsMenu"));
      assertTrue(html.contains("pwd1"));
      assertTrue(html.contains("pwd2"));
      assertTrue(html.contains("javax.faces.FormSignature")
            || html.contains("FormSignature"));
   }

   private static void assertMediaTags(HtmlPage page)
   {
      assertNotNull(page.getElementById("mainForm:tag-image"));
      assertTrue(page.getElementById("mainForm:tag-image").getAttribute("src").length() > 0);
      assertNotNull(page.getElementById("mainForm:tag-upload"));
      assertTrue(page.getElementById("mainForm:tag-upload").getAttribute("type").equalsIgnoreCase("file"));
   }

   private static void assertCommandTags(HtmlPage page)
   {
      String html = page.asXml();
      assertTrue(html.contains("Seam link"));
      assertTrue(html.contains("Seam button"));
      assertTrue(html.contains("Download text"));
      assertTrue(html.contains("remote.js") || html.contains("tag-remote"));
   }

   private static void assertConverterTags(HtmlPage page)
   {
      assertNotNull(page.getElementById("tag-convertDateTime"));
      assertTrue(page.getElementById("tag-convertDateTime").getTextContent().matches(".*\\d{2}:\\d{2}:\\d{2}.*"));

      String html = page.asXml();
      assertTrue(html.contains("mainForm:tag-convertEnum"));
      assertTrue(html.contains("ACTIVE") || html.contains("PENDING") || html.contains("CLOSED"));
      assertTrue(html.contains("mainForm:tag-convertEntity"));
      assertTrue(html.contains("Seamland"));
   }
}
