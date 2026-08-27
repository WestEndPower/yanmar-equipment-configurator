/*
 * West End Power universal configurator brand profile.
 *
 * The current Yanmar configurator is the visual and functional baseline.
 * Brand profiles extend that baseline without changing its default behavior.
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
      baseline: 'yanmar',
      colors: Object.freeze({
        accent: '#cc0000',
        dark: '#111111',
        surface: '#f5f5f5',
        border: '#dddddd',
        success: '#1f7a3a',
        danger: '#b00020'
      }),
      layout: Object.freeze({
        maxWidth: '1180px'
      }),
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

  function hasCapability(brandId, capability, fallbackValue) {
    const profile = getBrandProfile(brandId);
    const key = String(capability || '').trim();

    if(
      !profile ||
      !key ||
      !Object.prototype.hasOwnProperty.call(profile.capabilities, key)
    ){
      return fallbackValue !== false;
    }

    return profile.capabilities[key] === true;
  }

  return Object.freeze({
    SCHEMA_VERSION,
    profiles,
    getBrandProfile,
    requireBrandProfile,
    hasCapability
  });
});
