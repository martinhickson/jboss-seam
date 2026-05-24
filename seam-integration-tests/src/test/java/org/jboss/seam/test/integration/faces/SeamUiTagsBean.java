package org.jboss.seam.test.integration.faces;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import jakarta.persistence.EntityManager;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Create;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Transactional;
import org.jboss.seam.jsf.ListDataModel;
import org.jboss.seam.test.integration.Country;

/**
 * Backing bean for {@link SeamUiTagsTest} and {@link SeamUiConverterTagsTest}.
 */
@Name("seamUiTagsBean")
@Scope(ScopeType.EVENT)
public class SeamUiTagsBean implements Serializable
{
   private static final long serialVersionUID = 1L;

   private static final byte[] PNG_1X1 = Base64.getDecoder().decode(
         "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==");

   public enum Color
   {
      RED, BLUE, GREEN
   }

   public enum Status
   {
      ACTIVE, PENDING, CLOSED
   }

   @In(create = true)
   private EntityManager entityManager;

   @NotNull
   @Size(min = 1, max = 50)
   private String name = "Seam";

   private Color color = Color.RED;

   private Status status = Status.ACTIVE;

   private Date sampleTime;

   private Country selectedCountry;

   private List<Country> countries;

   private String selectedItem = "alpha";

   private String bio = "Hello *world*";

   private String formattedText = "Formatted *Seam* text";

   private String password;

   private String passwordVerify;

   private byte[] uploadData;

   private String uploadContentType;

   private String uploadFileName;

   private final ListDataModel selectionModel = new ListDataModel(
         Arrays.asList("alpha", "beta"));

   @Create
   @Transactional
   public void initConverterFixtures()
   {
      Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
      calendar.set(2020, Calendar.JANUARY, 15, 14, 30, 45);
      calendar.set(Calendar.MILLISECOND, 0);
      sampleTime = calendar.getTime();

      Long countryCount = entityManager.createQuery("select count(c) from Country c", Long.class)
            .getSingleResult();
      if (countryCount == 0)
      {
         Country country = new Country();
         country.setName("Seamland");
         entityManager.persist(country);
         entityManager.flush();
      }
      countries = entityManager.createQuery("select c from Country c order by c.name", Country.class).getResultList();
      selectedCountry = countries.isEmpty() ? null : countries.get(0);
   }

   public String getName()
   {
      return name;
   }

   public void setName(String name)
   {
      this.name = name;
   }

   public Color getColor()
   {
      return color;
   }

   public void setColor(Color color)
   {
      this.color = color;
   }

   public Status getStatus()
   {
      return status;
   }

   public void setStatus(Status status)
   {
      this.status = status;
   }

   public List<Status> getStatuses()
   {
      return Arrays.asList(Status.values());
   }

   public Date getSampleTime()
   {
      return sampleTime;
   }

   public Country getSelectedCountry()
   {
      return selectedCountry;
   }

   public void setSelectedCountry(Country selectedCountry)
   {
      this.selectedCountry = selectedCountry;
   }

   public List<Country> getCountries()
   {
      return countries;
   }

   public String getSelectedItem()
   {
      return selectedItem;
   }

   public void setSelectedItem(String selectedItem)
   {
      this.selectedItem = selectedItem;
   }

   public List<String> getItems()
   {
      return Arrays.asList("alpha", "beta", "gamma");
   }

   public String getBio()
   {
      return bio;
   }

   public void setBio(String bio)
   {
      this.bio = bio;
   }

   public String getFormattedText()
   {
      return formattedText;
   }

   public String getPassword()
   {
      return password;
   }

   public void setPassword(String password)
   {
      this.password = password;
   }

   public String getPasswordVerify()
   {
      return passwordVerify;
   }

   public void setPasswordVerify(String passwordVerify)
   {
      this.passwordVerify = passwordVerify;
   }

   public byte[] getImageData()
   {
      return PNG_1X1;
   }

   public byte[] getFileData()
   {
      return "Seam resource data".getBytes();
   }

   public byte[] getUploadData()
   {
      return uploadData;
   }

   public void setUploadData(byte[] uploadData)
   {
      this.uploadData = uploadData;
   }

   public String getUploadContentType()
   {
      return uploadContentType;
   }

   public void setUploadContentType(String uploadContentType)
   {
      this.uploadContentType = uploadContentType;
   }

   public String getUploadFileName()
   {
      return uploadFileName;
   }

   public void setUploadFileName(String uploadFileName)
   {
      this.uploadFileName = uploadFileName;
   }

   public ListDataModel getSelectionModel()
   {
      return selectionModel;
   }

   public String noop()
   {
      return null;
   }
}
