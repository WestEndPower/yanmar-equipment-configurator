/*
 * West End Power universal configurator brand profile.
 *
 * Phase 1 is intentionally non-invasive: index.html does not load this file yet.
 * The current Yanmar configurator remains the visual and functional baseline.
 */
(function attachBrandProfile(root, factory) {
  const api = factory();

  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }

  if (root) {
    root.WestEndConfiguratorBrand = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createBrandProfileApi() {
  'use strict';

  const SCHEMA_VERSION = 1;

  const YANMAR_BASELINE = Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    id: 'YANMAR',
    name: 'Yanmar',
    role: 'baseline',
    appearance: Object.freeze({
      preserveCurrentLayout: true,
      preserveCurrentQuoteLayout: true,
      preserveCurrentDealerControls: true
    }),
    capabilities: Object.freeze({
      publicConfigurator: true,
      dealerMode: true,
      quotes: true,
      salesOrders: true,
      onlineOrders: true,
      financing: true,
      freightRules: true,
      promotions: true,
      inventory: true
    })
  });

  const profiles = Object.freeze({
    YANMAR: YANMAR_BASELINE
  });

  function normalizeBrandId(value) {
    return String(value || '').trim().toUpperCase();
  }

  function getBrandProfile(brandId) {
    const key = normalizeBrandId(brandId);
    return profiles[key] || null;
  }

  function requireBrandProfile(brandId) {
    const profile = getBrandProfile(brandId);

    if (!profile) {
      throw new Error('Unknown configurator brand: ' + normalizeBrandId(brandId));
    }

    return profile;
  }

  return Object.freeze({
    SCHEMA_VERSION,
    profiles,
    getBrandProfile,
    requireBrandProfile
  });
});
