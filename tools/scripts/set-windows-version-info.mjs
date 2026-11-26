// Rewrites the VERSIONINFO resource and the icon of the Windows executable
// produced by pkg.
//
// pkg output is a renamed node.exe whose metadata still says "Node.js" /
// "node.exe". Code signing such a binary as Bright Security creates a
// publisher/metadata mismatch, which is a heuristic signal for SmartScreen and
// Defender. This script makes the file identify itself as Bright CLI, and must
// run BEFORE the executable is signed (resedit strips any existing signature).
//
// resedit is used instead of rcedit because rcedit is known to corrupt
// pkg-generated binaries ("Pkg: Error reading from file").
//
// Usage: node tools/scripts/set-windows-version-info.mjs <path-to-exe> [--no-icon]

import fs from 'node:fs';
import path from 'node:path';
import * as ResEdit from 'resedit';

const COMPANY_NAME = 'Bright Security LTD'; // must match the "O" of the code signing certificate
const PRODUCT_NAME = 'Bright CLI';
const FILE_DESCRIPTION = 'Bright CLI';
const ORIGINAL_FILENAME = 'bright-cli.exe';
const INTERNAL_NAME = 'bright-cli';
const LEGAL_COPYRIGHT = `Copyright (c) ${new Date().getUTCFullYear()} ${COMPANY_NAME}. MIT license.`;
const ICON_PATH = path.join('tools', 'resources', 'logo.ico');

const args = process.argv.slice(2);
const exePath = args.find((a) => !a.startsWith('--'));
const withIcon = !args.includes('--no-icon');

if (!exePath) {
  console.error(
    'Usage: node tools/scripts/set-windows-version-info.mjs <path-to-exe> [--no-icon]'
  );
  process.exit(1);
}
if (!fs.existsSync(exePath)) {
  console.error(`File to stamp not found: ${exePath}`);
  process.exit(1);
}

// Windows FileVersion/ProductVersion must be numeric "a.b.c.d". Pre-release
// versions such as 13.11.0-next.15 become 13.11.0.15 (same rule as build-msi.ps1).
const semver = JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
const numericParts = semver
  .replace(/([A-Za-z\-.])+/g, '.')
  .split('.')
  .filter(Boolean)
  .slice(0, 4)
  .map((p) => Number(p) % 65536);
while (numericParts.length < 4) numericParts.push(0);
const [major, minor, micro, revision] = numericParts;
const numericVersion = numericParts.join('.');

console.log(`Stamping "${exePath}" with version ${numericVersion} (${semver})`);

// `ignoreCert` lets the script run on an already signed file (local
// experiments); the output is always unsigned and must be signed afterwards.
const exe = ResEdit.NtExecutable.from(fs.readFileSync(exePath), {
  ignoreCert: true
});
const res = ResEdit.NtExecutableResource.from(exe);

// -- version info
const viList = ResEdit.Resource.VersionInfo.fromEntries(res.entries);
const vi = viList.length
  ? viList[0]
  : ResEdit.Resource.VersionInfo.createEmpty();
const translations = vi.getAllLanguagesForStringValues();
const lang = translations.length ? translations[0].lang : 1033;
const codepage = translations.length ? translations[0].codepage : 1200;

vi.setFileVersion(major, minor, micro, revision, lang);
vi.setProductVersion(major, minor, micro, revision, lang);
vi.setStringValues(
  { lang, codepage },
  {
    CompanyName: COMPANY_NAME,
    ProductName: PRODUCT_NAME,
    FileDescription: FILE_DESCRIPTION,
    OriginalFilename: ORIGINAL_FILENAME,
    InternalName: INTERNAL_NAME,
    LegalCopyright: LEGAL_COPYRIGHT,
    FileVersion: numericVersion,
    ProductVersion: semver
  }
);
vi.outputToResourceEntries(res.entries);

// -- icon
if (withIcon) {
  const iconGroups = ResEdit.Resource.IconGroupEntry.fromEntries(res.entries);
  if (iconGroups.length) {
    const iconFile = ResEdit.Data.IconFile.from(fs.readFileSync(ICON_PATH));
    ResEdit.Resource.IconGroupEntry.replaceIconsForResource(
      res.entries,
      iconGroups[0].id,
      iconGroups[0].lang,
      iconFile.icons.map((item) => item.data)
    );
    console.log(`Replaced icon group ${iconGroups[0].id} with ${ICON_PATH}`);
  } else {
    console.log('No icon group found in the executable; icon not replaced');
  }
}

res.outputResource(exe);
fs.writeFileSync(exePath, Buffer.from(exe.generate()));

// -- print the result for the CI log
const check = ResEdit.NtExecutableResource.from(
  ResEdit.NtExecutable.from(fs.readFileSync(exePath), { ignoreCert: true })
);
const result = ResEdit.Resource.VersionInfo.fromEntries(check.entries)[0];
console.log(
  'Resulting version info:',
  result.getStringValues({ lang, codepage })
);
console.log('Done');
