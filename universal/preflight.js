'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  execFileSync
} = require('node:child_process');

const projectRoot =
  path.resolve(__dirname, '..');

const indexPath =
  path.join(projectRoot, 'index.html');

const javascriptFiles = [
  'universal/brand-profile.js',
  'universal/brand-profile-template.js',
  'universal/brand-profile.test.js',
  'universal/brand-profile-template.test.js'
];

const testFiles = [
  'universal/brand-profile.test.js',
  'universal/brand-profile-template.test.js'
];

function runNode(args) {
  return execFileSync(
    process.execPath,
    args,
    {
      cwd: projectRoot,
      encoding: 'utf8',
      stdio: [
        'ignore',
        'pipe',
        'pipe'
      ]
    }
  ).trim();
}

function pass(message) {
  console.log('PASS — ' + message);
}

javascriptFiles.forEach((file) => {
  runNode(['--check', file]);
  pass(file + ' syntax');
});

testFiles.forEach((file) => {
  const output = runNode([file]);

  assert.match(
    output,
    /tests passed\./
  );

  pass(file);
});

const indexHtml =
  fs.readFileSync(indexPath, 'utf8');

const requiredIndexMarkers = [
  'data-configurator-brand="YANMAR"',
  'const ACTIVE_BRAND_ID =',
  'dataProfileApi.getActiveBrandId(document)',
  'dataProfileApi.getDataFiles(',
  'brandApi.validateBrandProfile(',
  'Universal brand-profile service is unavailable.',
  'fallbackBrandId + \'ATTACHMENT\'',
  'fallbackBrandId + \'ACCESSORY\''
];

requiredIndexMarkers.forEach((marker) => {
  assert.ok(
    indexHtml.includes(marker),
    'Missing index marker: ' + marker
  );
});

pass('universal index integration markers');

const forbiddenFreightLiterals = [
  '\'YANMARATTACHMENT\'',
  '\'YANMARACCESSORY\'',
  '"YANMARATTACHMENT"',
  '"YANMARACCESSORY"'
];

forbiddenFreightLiterals.forEach((literal) => {
  assert.equal(
    indexHtml.includes(literal),
    false,
    'Hard-coded freight literal remains: ' +
      literal
  );
});

pass('no hard-coded Yanmar freight groups');

const profileScriptPosition =
  indexHtml.indexOf(
    '<script src="universal/brand-profile.js">'
  );

const configuratorScriptPosition =
  indexHtml.indexOf(
    '(function(){',
    profileScriptPosition
  );

assert.ok(
  profileScriptPosition >= 0,
  'Brand-profile script tag is missing.'
);

assert.ok(
  configuratorScriptPosition >
    profileScriptPosition,
  'Brand-profile API must load before the configurator.'
);

pass('brand profile loads before configurator');

const brandApi =
  require('./brand-profile.js');

const registryValidation =
  brandApi.validateRegisteredProfiles();

assert.equal(
  registryValidation.valid,
  true,
  registryValidation.errors.join('\n')
);

assert.equal(
  brandApi.getActiveBrandId(),
  'YANMAR'
);

assert.equal(
  brandApi.getBrandProfile('YANMAR')?.role,
  'baseline'
);

pass('protected Yanmar baseline');

console.log(
  '\nUniversal configurator preflight passed.'
);