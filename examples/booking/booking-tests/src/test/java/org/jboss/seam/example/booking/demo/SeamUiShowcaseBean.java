package org.jboss.seam.example.booking.demo;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.jsf.ListDataModel;

@Name("seamUiShowcase")
@Scope(ScopeType.EVENT)
public class SeamUiShowcaseBean implements Serializable
{
   private static final long serialVersionUID = 1L;

   private static final byte[] HOTEL_BADGE = Base64.getDecoder().decode(
         "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");

   public enum RoomTier
   {
      STANDARD, DELUXE, SUITE
   }

   @NotNull
   @Size(min = 1, max = 80)
   private String guestName = "Jordan Rivers";

   private RoomTier tier = RoomTier.DELUXE;

   private String selectedAmenity = "Late checkout";

   private String travelNotes = "Arriving after *midnight* — quiet room preferred";

   private String welcomeMessage = "Welcome to the *Seam Booking* UI gallery";

   private String confirmPassword;

   private String confirmPasswordVerify;

   private byte[] uploadData;

   private String uploadContentType;

   private String uploadFileName;

   private final ListDataModel selectionModel = new ListDataModel(
         Arrays.asList("Ocean view", "City view", "Garden patio"));

   public String getGuestName()
   {
      return guestName;
   }

   public void setGuestName(String guestName)
   {
      this.guestName = guestName;
   }

   public RoomTier getTier()
   {
      return tier;
   }

   public void setTier(RoomTier tier)
   {
      this.tier = tier;
   }

   public String getSelectedAmenity()
   {
      return selectedAmenity;
   }

   public void setSelectedAmenity(String selectedAmenity)
   {
      this.selectedAmenity = selectedAmenity;
   }

   public List<String> getAmenities()
   {
      return Arrays.asList("Late checkout", "Airport shuttle", "Spa credit", "Club lounge");
   }

   public String getTravelNotes()
   {
      return travelNotes;
   }

   public void setTravelNotes(String travelNotes)
   {
      this.travelNotes = travelNotes;
   }

   public String getWelcomeMessage()
   {
      return welcomeMessage;
   }

   public String getConfirmPassword()
   {
      return confirmPassword;
   }

   public void setConfirmPassword(String confirmPassword)
   {
      this.confirmPassword = confirmPassword;
   }

   public String getConfirmPasswordVerify()
   {
      return confirmPasswordVerify;
   }

   public void setConfirmPasswordVerify(String confirmPasswordVerify)
   {
      this.confirmPasswordVerify = confirmPasswordVerify;
   }

   public byte[] getBadgeImage()
   {
      return HOTEL_BADGE;
   }

   public byte[] getBrochureData()
   {
      return ("Seam Booking Demo — " + guestName + "\nTier: " + tier + "\n").getBytes();
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

   public String savePreferences()
   {
      return null;
   }
}
