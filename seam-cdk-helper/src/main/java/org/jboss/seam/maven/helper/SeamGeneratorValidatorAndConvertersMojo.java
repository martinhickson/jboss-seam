package org.jboss.seam.maven.helper;


import java.io.File;
import java.io.FileNotFoundException;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;

/**
 * Appends converter and validator Facelets tags to the CDK-generated
 * {@code s.taglib.xml}. Converter tags come from
 * {@code src/main/config/component} {@code <converter>} fragments, not from a
 * {@code @FacesConverter} scan of {@code src/main/java}.
 *
 * @goal execute
 * @phase generate-sources
 *
 * @author Rafael Benevides <https://community.jboss.org/people/rafabene>
 * @author Marek Novotny <https://community.jboss.org/people/manaRH>
 */
public class SeamGeneratorValidatorAndConvertersMojo extends AbstractMojo
{
   /**
    * The source directories containing the sources to be compiled.
    *
    * @parameter expression="${project.build.sourceDirectory}"
    * @required
    * @readonly
    */
   protected String sourceDirectory;

   /**
    * Module base directory. Converter/validator XML lives under
    * {@code src/main/config/component} here.
    *
    * @parameter expression="${project.basedir}"
    * @required
    * @readonly
    */
   private File basedir;

   /**
    * Output directory for processed resources
    *
    * @parameter expression="${project.build.directory}"
    * @required
    */
   private String targetDirectory;

   private ConverterGenerator converterGenerator;
   private ValidatorGenerator validatorGenerator;

   public void execute() throws MojoExecutionException
   {
      File componentConfigDirectory = new File(basedir, "src/main/config/component");
      converterGenerator = new ConverterGenerator(sourceDirectory, componentConfigDirectory, targetDirectory, getLog());
      validatorGenerator = new ValidatorGenerator(targetDirectory, getLog());
      try
      {
         File sourceFolder = new File(sourceDirectory);
         getLog().info("Source Folder: " + sourceFolder);
         visitFolder(sourceFolder);
         File generatedJakarta = new File(basedir, "src/generated/jakarta");
         if (generatedJakarta.isDirectory())
         {
            getLog().info("Generated Jakarta source folder: " + generatedJakarta);
            visitFolder(generatedJakarta);
         }
         if (componentConfigDirectory.isDirectory())
         {
            getLog().info("Component config folder: " + componentConfigDirectory);
            visitFolder(componentConfigDirectory);
         }
         converterGenerator.generateConverters();
         validatorGenerator.generateValidators();
      }
      catch (Exception e)
      {
         throw new MojoExecutionException("Error on Generator", e);
      }

   }

   private void visitFolder(File sourceFolder) throws FileNotFoundException
   {
      File[] files = sourceFolder.listFiles();
      if (files == null)
      {
         return;
      }
      for (File file : files)
      {
         if (file.isDirectory())
         {
            visitFolder(file);
         }
         else
         {
            converterGenerator.addFile(file);
            validatorGenerator.addFile(file);
         }
      }
   }
}
