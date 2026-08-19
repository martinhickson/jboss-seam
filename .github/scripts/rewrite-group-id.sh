#!/usr/bin/env bash
# Rewrite this project's Maven groupId in POM files without committing.
# Used by Release to publish GitHub Packages as org.jboss.seam (original)
# and Maven Central as io.github.martinhickson, same version.
set -euo pipefail

print_project_group_id() {
  # Skip commented-out groupId lines (root POM still has a jboss-parent comment).
  grep '<groupId>' "$1" | grep -v '<!--' | head -1 | sed -E 's/.*<groupId>([^<]+)<\/groupId>.*/\1/'
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${root}"

if [ "${1:-}" = "--print" ]; then
  print_project_group_id "${2:-pom.xml}"
  exit 0
fi

FROM_GROUP="${1:?from groupId required, e.g. io.github.martinhickson}"
TO_GROUP="${2:?to groupId required, e.g. org.jboss.seam}"

if [ "${FROM_GROUP}" = "${TO_GROUP}" ]; then
  echo "GroupId already ${TO_GROUP}; nothing to rewrite"
  exit 0
fi

echo "Rewriting groupId ${FROM_GROUP} -> ${TO_GROUP}"

# Nested vendor trees and the pinned CDK helper stay on their own coordinates.
# seam-cdk-helper is version 1.0.1 (not the Seam release version) and is
# resolved from GitHub Packages / the prior install as io.github.martinhickson.
find . -name pom.xml \
  -not -path './.git/*' \
  -not -path '*/target/*' \
  -not -path './genericmessagingra/*' \
  -not -path './richfaces/*' \
  -not -path './richfaces4-core/*' \
  -not -path './richfaces-cdk/*' \
  -not -path './seam-cdk-helper/*' \
  -print0 |
while IFS= read -r -d '' pom; do
  awk -v from="${FROM_GROUP}" -v to="${TO_GROUP}" '
    BEGIN { in_plugin = 0; skip = 0; buf = "" }
    /<plugin>/ {
      in_plugin = 1
      skip = 0
      buf = $0 ORS
      next
    }
    in_plugin {
      buf = buf $0 ORS
      if ($0 ~ /<artifactId>[[:space:]]*seam-cdk-helper[[:space:]]*<\/artifactId>/) {
        skip = 1
      }
      if ($0 ~ /<\/plugin>/) {
        if (!skip) {
          gsub("<groupId>" from "</groupId>", "<groupId>" to "</groupId>", buf)
        }
        printf "%s", buf
        in_plugin = 0
        buf = ""
      }
      next
    }
    {
      gsub("<groupId>" from "</groupId>", "<groupId>" to "</groupId>")
      print
    }
  ' "${pom}" > "${pom}.groupid.tmp"
  mv "${pom}.groupid.tmp" "${pom}"
done

echo "Root groupId: $(print_project_group_id pom.xml)"
echo "BOM groupId: $(print_project_group_id bom/pom.xml)"
echo "Sample parent groupId: $(print_project_group_id jboss-seam-jakarta/pom.xml)"
