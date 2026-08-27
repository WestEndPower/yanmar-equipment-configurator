'use strict';

const assert = require('node:assert/strict');
const api = require('./brand-profile.js');

const registeredResult = api.validateRegisteredProfiles();

assert.equal(
  registeredResult.valid,
  true,
  registeredResult.errors.join('\n')
);

assert.equal(api.getBrandProfile('yanmar')?.id, 'YANMAR');
assert.equal(api.getBrandProfile(' YANMAR ')?.id, 'YANMAR');
assert.equal(api.getBrandProfile('unknown'), null);

assert.throws(
  () => api.requireBrandProfile('unknown'),
  /Unknown configurator brand: UNKNOWN/
);

const invalidProfile = {
  schemaVersion: api.SCHEMA_VERSION,
  id: 'test',
  name: '',
  role: 'brand',
  appearance: {
    baseline: 'yanmar',
    colors: {},
    layout: {}
  },
  data: {
    files: {}
  },
  freight: {
    packageComponentGroups: [],
    ruleIdPrefixes: []
  },
  capabilities: {}
};

const invalidResult = api.validateBrandProfile(invalidProfile);

assert.equal(invalidResult.valid, false);
assert.ok(invalidResult.errors.length > 0);
assert.ok(
  invalidResult.errors.includes(
    'profile.id must be uppercase and trimmed.'
  )
);
assert.ok(
  invalidResult.errors.includes(
    'profile.data.files.products must be a non-empty string.'
  )
);
assert.ok(
  invalidResult.errors.includes(
    'profile.capabilities.financing must be boolean.'
  )
);

console.log('Brand-profile validator tests passed.');