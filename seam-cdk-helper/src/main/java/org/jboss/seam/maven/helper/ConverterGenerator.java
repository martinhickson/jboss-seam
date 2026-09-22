package org.jboss.seam.maven.helper;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import org.apache.maven.plugin.logging.Log;
import org.w3c.dom.Element;

/**
 * Generates Facelets tags for Seam converters.
 *
 * RichFaces CDK does not emit {@code <tag>} entries for faces-config
 * {@code <converter>} fragments (JBSEAM-4955 / RF-12271). The Jakarta UI
 * module also keeps converter Java under {@code src/generated/jakarta}, so a
 * {@code @FacesConverter} scan of {@code src/main/java} finds nothing.
 * Converter XML in {@code src/main/config/component} is the source of truth
 * for tag names, matching how {@link ValidatorGenerator} works.
 */
public class ConverterGenerator
{

   private final List<File> converterConfigs = new ArrayList<File>();
   private final List<File> converterSources = new ArrayList<File>();
   private final Log log;
   private final String sourceDirectory;
   private final File componentConfigDirectory;
   private final String targetDirectory;

   public ConverterGenerator(String sourceDirectory, File componentConfigDirectory, String targetDirectory, Log log)
   {
      this.sourceDirectory = sourceDirectory;
      this.componentConfigDirectory = componentConfigDirectory;
      this.targetDirectory = targetDirectory;
      this.log = log;
   }

   public void addFile(File file) throws FileNotFoundException
   {
      if (fileIsConverterConfig(file))
      {
         converterConfigs.add(file);
      }
      else if (fileIsConverterSource(file))
      {
         converterSources.add(file);
      }
   }

   private boolean fileIsConverterConfig(File file) throws FileNotFoundException
   {
      if (!file.getName().endsWith(".xml"))
      {
         return false;
      }
      Scanner scanner = new Scanner(file);
      try
      {
         if (scanner.findWithinHorizon("<converter>", 0) != null)
         {
            log.info("Identified " + file.getName() + " as Converter XML");
            return true;
         }
      }
      finally
      {
         scanner.close();
      }
      return false;
   }

   private boolean fileIsConverterSource(File file) throws FileNotFoundException
   {
      if (!file.getName().endsWith(".java"))
      {
         return false;
      }
      Scanner scanner = new Scanner(file);
      try
      {
         if (scanner.findWithinHorizon("@FacesConverter", 0) != null)
         {
            log.info("Identified " + file.getName() + " as Converter source code");
            return true;
         }
      }
      finally
      {
         scanner.close();
      }
      return false;
   }

   public void generateConverters() throws Exception
   {
      log.info("Generating Converters");
      XMLGenerator xmlGenerator = new XMLGenerator(log);
      File outXML = new File(targetDirectory + "/generated-sources/main/resources/META-INF", "s.taglib.xml");
      Map<String, File> configsByTag = new LinkedHashMap<String, File>();

      for (File xml : converterConfigs)
      {
         configsByTag.put(tagNameForConfig(xml), xml);
      }

      for (File source : converterSources)
      {
         String classFromSource = getClassNameFromSource(source);
         File facesConfigXML = findCorrespondentConfig(classFromSource);
         if (facesConfigXML != null)
         {
            configsByTag.put(tagNameForConfig(facesConfigXML), facesConfigXML);
         }
         else
         {
            log.warn("No component config found for converter " + classFromSource);
         }
      }

      List<Element> tagsToAdd = new ArrayList<Element>();
      for (Map.Entry<String, File> entry : configsByTag.entrySet())
      {
         tagsToAdd.add(xmlGenerator.getFaceletsTagElementFromFacesconfig(entry.getValue(), entry.getKey(), "converter"));
      }
      log.info("Adding " + tagsToAdd.size() + " converter tags to " + outXML.getName());
      xmlGenerator.updateFile(outXML, tagsToAdd);
   }

   private static String tagNameForConfig(File xml)
   {
      return xml.getName().replace(".xml", "");
   }

   private String getClassNameFromSource(File source) throws FileNotFoundException
   {
      String simpleName = source.getName().replace(".java", "");
      Scanner scanner = new Scanner(source);
      try
      {
         while (scanner.hasNextLine())
         {
            String line = scanner.nextLine().trim();
            if (line.startsWith("package "))
            {
               String pkg = line.substring("package ".length()).replace(";", "").trim();
               return pkg + "." + simpleName;
            }
         }
      }
      finally
      {
         scanner.close();
      }

      String relativePath = source.getAbsolutePath().replace(sourceDirectory, "").replace(File.separatorChar, '.').replace(".java", "");
      if (relativePath.startsWith("."))
      {
         relativePath = relativePath.substring(1);
      }
      return relativePath;
   }

   private File findCorrespondentConfig(String classFromSource) throws FileNotFoundException
   {
      File componentFolder = componentConfigDirectory;
      if (componentFolder == null || !componentFolder.isDirectory())
      {
         String whereToFind = sourceDirectory.replace("/java", "/config/component");
         componentFolder = new File(whereToFind);
      }
      log.debug("Searching correspondent config for " + classFromSource + " in " + componentFolder);
      File[] files = componentFolder.listFiles();
      if (files == null)
      {
         return null;
      }
      for (File f : files)
      {
         if (!f.isFile())
         {
            continue;
         }
         Scanner scanner = new Scanner(f);
         try
         {
            if (scanner.findWithinHorizon(classFromSource, 0) != null)
            {
               return f;
            }
         }
         finally
         {
            scanner.close();
         }
      }
      return null;
   }

}
