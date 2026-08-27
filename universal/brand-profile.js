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
    data: Object.freeze({
      files: Object.freeze({
        products: 'data/products.csv',
        packages: 'data/packages.csv',
        compatibility: 'data/compatibility-runtime.csv',
        batteries: 'data/batteries.csv',
        chargers: 'data/chargers.csv',
        attachments: 'data/attachments.csv',
        accessories: 'data/accessories.csv',
        parts: 'data/parts.csv',
        promotions: 'data/promotions.csv',
        delivery: 'data/delivery-zones.csv',
        financePrograms: 'data/finance-programs.csv',
        bidFleet: 'data/bid-fleet-programs.csv',
        freightRules: 'data/freight-rules.csv'
      })
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

  function applyAppearance(brandId, targetDocument) {
    const profile = getBrandProfile(brandId);
    const documentRef = targetDocument ||
      (typeof document === 'object' ? document : null);
    const rootElement = documentRef?.documentElement;

    if(!profile || !rootElement){
      return null;
    }

    const colors = profile.appearance?.colors || {};
    const layout = profile.appearance?.layout || {};
    const variables = {
      '--config-accent': colors.accent,
      '--config-dark': colors.dark,
      '--config-surface': colors.surface,
      '--config-border': colors.border,
      '--config-success': colors.success,
      '--config-danger': colors.danger,
      '--config-max-width': layout.maxWidth,
      '--stihl-orange': colors.accent,
      '--stihl-dark': colors.dark,
      '--stihl-gray': colors.surface,
      '--stihl-border': colors.border,
      '--stihl-green': colors.success,
      '--stihl-red': colors.danger,
      '--max-width': layout.maxWidth
    };

    Object.entries(variables).forEach(([name, value]) => {
      const normalizedValue = String(value || '').trim();

      if(normalizedValue){
        rootElement.style.setProperty(name, normalizedValue);
      }
    });

    rootElement.dataset.configuratorBrand = profile.id.toLowerCase();
    return profile.appearance;
  }

  return Object.freeze({
    SCHEMA_VERSION,
    profiles,
    getBrandProfile,
    requireBrandProfile,
    hasCapability,
    applyAppearance
  });
});
