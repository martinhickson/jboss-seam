# PowerShell script to generate exclusion list from jakarta directory
# Run this when you add/remove files in src/main/java

$jakartaDir = "src/main/java"
$exclusionFile1 = "pom-exclusions.xml"
$exclusionFile2 = "pom-exclusions-alt.xml"

# Find all Java files in jakarta directory and generate XML exclusion patterns
$exclusions = Get-ChildItem -Path $jakartaDir -Filter "*.java" -Recurse -File |
    ForEach-Object {
        # Convert full path to relative path from jakarta directory
        $jakartaFullPath = Join-Path $PWD $jakartaDir
        $relativePath = $_.FullName -replace [regex]::Escape("$jakartaFullPath\"), "" -replace "\\", "/"
        # Original indentation: tab + 36 spaces (for maven-resources-plugin)
        "`t" + "                                    " + "<exclude>**/$relativePath</exclude>"
    } |
    Sort-Object

# Alternative format: exclusions/exclusion (for other Maven plugins)
$exclusionsAlt = Get-ChildItem -Path $jakartaDir -Filter "*.java" -Recurse -File |
    ForEach-Object {
        # Convert full path to relative path from jakarta directory
        $jakartaFullPath = Join-Path $PWD $jakartaDir
        $relativePath = $_.FullName -replace [regex]::Escape("$jakartaFullPath\"), "" -replace "\\", "/"
        # Adjusted indentation: tab + 20 spaces (36 - 16 = 20 spaces total, for second format)
        "`t" + "                    " + "<exclusion>**/$relativePath</exclusion>"
    } |
    Sort-Object

# Generate the first XML block with <excludes>/<exclude> (for maven-resources-plugin)
$xmlContent1 = "                                    <excludes>" + "`n"
$xmlContent1 += ($exclusions -join "`n") + "`n"
$xmlContent1 += "                                    </excludes>"

# Generate the second XML block with <exclusions>/<exclusion> (alternative format)
$xmlContent2 = "                    <exclusions>" + "`n"
$xmlContent2 += ($exclusionsAlt -join "`n") + "`n"
$xmlContent2 += "                    </exclusions>"

# Output both files
$xmlContent1 | Out-File -FilePath $exclusionFile1 -Encoding UTF8
$xmlContent2 | Out-File -FilePath $exclusionFile2 -Encoding UTF8

Write-Host "Generated XML exclusions (format 1 - excludes/exclude): $exclusionFile1"
Write-Host "Generated XML exclusions (format 2 - exclusions/exclusion): $exclusionFile2"
Write-Host "Copy the appropriate format into your pom.xml configuration"
