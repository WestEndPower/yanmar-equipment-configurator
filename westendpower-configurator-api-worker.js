// UPS Rating API enabled
let upsTokenCache = {
  token: "",
  expiresAt: 0
};

const ONLINE_TERMS_VERSION =
  "2026-08-06-v1";

const ONLINE_TERMS_TEXT =
  "All purchases are final. Please contact West End Power Equipment prior to ordering if you are unsure whether the item(s) selected are correct for or compatible with your application. I have read and understand these terms and have verified that the item(s) selected are correct for my application, or I have contacted West End Power Equipment to confirm fitment or compatibility.";

/*
  UNIVERSAL BRAND REGISTRY

  Add a brand here before enabling its public configurator.
  This one registry controls protected pricing, finance,
  Dealer Mode data, private sync and sales-order storage.
*/
const SUPPORTED_BRANDS = Object.freeze({
  STIHL: Object.freeze({
    brandName:"STIHL",
    configuratorTitle:"STIHL Equipment Configurator"
  }),

  HONDA: Object.freeze({
    brandName:"Honda",
    configuratorTitle:"Honda Power Equipment Configurator"
  }),


  YANMAR: Object.freeze({
    brandName:"Yanmar",
    configuratorTitle:"Yanmar Equipment Configurator"
  }),


  TORO: Object.freeze({
    brandName:"Toro",
    configuratorTitle:"Toro Equipment Configurator"
  })
});

function normalizeSupportedBrand(value){
  const brandId =
    String(value || "")
      .trim()
      .toUpperCase();

  return Object.prototype.hasOwnProperty.call(
    SUPPORTED_BRANDS,
    brandId
  )
    ? brandId
    : "";
}

function supportedBrandConfig(brandId){
  return SUPPORTED_BRANDS[
    normalizeSupportedBrand(brandId)
  ] || null;
}

const ALLOWED_BROWSER_ORIGINS = new Set([
  "https://westendpower.github.io",
  "https://www.westendpower.com",
  "https://westendpower.com",
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "http://127.0.0.1:5501",
  "http://localhost:5501"
]);

function browserCorsHeaders(request){
  const origin = String(request.headers.get("Origin") || "");
  const headers = {
    "Access-Control-Allow-Methods":"POST, OPTIONS",
    "Access-Control-Allow-Headers":"Content-Type, X-Dealer-Password, X-Dealer-Session",
    "Vary":"Origin"
  };

  if(ALLOWED_BROWSER_ORIGINS.has(origin)){
    headers["Access-Control-Allow-Origin"] = origin;
  }
  return headers;
}

function staffAuthorizationResponse(request, env){
  const expectedUser = String(env.QUOTE_ADMIN_USER || "");
  const expectedPassword = String(env.QUOTE_ADMIN_PASSWORD || "");

  if(!expectedUser || !expectedPassword){
    return new Response("Staff access is not configured.", { status:503 });
  }

  const header = String(request.headers.get("Authorization") || "");
  let suppliedUser = "";
  let suppliedPassword = "";

  if(header.startsWith("Basic ")){
    try{
      const decoded = atob(header.slice(6));
      const separator = decoded.indexOf(":");
      if(separator >= 0){
        suppliedUser = decoded.slice(0, separator);
        suppliedPassword = decoded.slice(separator + 1);
      }
    }catch(_error){}
  }

  if(suppliedUser === expectedUser && suppliedPassword === expectedPassword){
    return null;
  }

  return new Response("Authentication required.", {
    status:401,
    headers:{
      "WWW-Authenticate":'Basic realm="West End Power Staff", charset="UTF-8"',
      "Cache-Control":"no-store"
    }
  });
}

function dealerAuthorizationResponse(request, env, corsHeaders){
  const expectedPassword = String(env.CONFIG_DEALER_PASSWORD || "");
  const suppliedPassword = String(
    request.headers.get("X-Dealer-Password") || ""
  );

  if(!expectedPassword){
    return Response.json(
      { error:"Dealer access is not configured." },
      {
        status:503,
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );
  }

  if(suppliedPassword === expectedPassword){
    return null;
  }

  return Response.json(
    { error:"Authentication required." },
    {
      status:401,
      headers:{
        ...corsHeaders,
        "Cache-Control":"no-store"
      }
    }
  );
}

function base64UrlEncodeBytes(bytes){
  let binary = "";

  for(const byte of bytes){
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function base64UrlDecodeBytes(value){
  const normalized =
    String(value || "")
      .replaceAll("-", "+")
      .replaceAll("_", "/");

  const padded =
    normalized +
    "=".repeat((4 - normalized.length % 4) % 4);

  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );
}

async function dealerSessionKey(env){
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(
      String(env.CONFIG_DEALER_PASSWORD || "")
    ),
    {
      name:"HMAC",
      hash:"SHA-256"
    },
    false,
    ["sign","verify"]
  );
}

async function createDealerSessionToken(env, brandId){
  const payload = {
    brandId:String(brandId || "").toUpperCase(),
    expiresAt:Date.now() + (8 * 60 * 60 * 1000),
    nonce:crypto.randomUUID()
  };

  const encodedPayload =
    base64UrlEncodeBytes(
      new TextEncoder().encode(
        JSON.stringify(payload)
      )
    );

  const signature =
    await crypto.subtle.sign(
      "HMAC",
      await dealerSessionKey(env),
      new TextEncoder().encode(encodedPayload)
    );

  return (
    encodedPayload +
    "." +
    base64UrlEncodeBytes(
      new Uint8Array(signature)
    )
  );
}

async function verifyDealerSessionToken(
  request,
  env,
  requiredBrandId
){
  try{
    const token =
      String(
        request.headers.get(
          "X-Dealer-Session"
        ) || ""
      );

    const parts = token.split(".");

    if(parts.length !== 2){
      return false;
    }

    const validSignature =
      await crypto.subtle.verify(
        "HMAC",
        await dealerSessionKey(env),
        base64UrlDecodeBytes(parts[1]),
        new TextEncoder().encode(parts[0])
      );

    if(!validSignature){
      return false;
    }

    const payload =
      JSON.parse(
        new TextDecoder().decode(
          base64UrlDecodeBytes(parts[0])
        )
      );

    return (
      Number(payload.expiresAt) > Date.now() &&
      String(payload.brandId || "").toUpperCase() ===
        String(requiredBrandId || "").toUpperCase()
    );

  }catch(_error){
    return false;
  }
}

let lastRateLimitCleanup = 0;

async function rateLimitClientKey(request){

  const ip =
    String(
      request.headers.get(
        "CF-Connecting-IP"
      ) || "unknown"
    );

  const encoded =
    new TextEncoder().encode(ip);

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      encoded
    );

  return Array
    .from(
      new Uint8Array(digest)
    )
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("")
    .slice(0, 32);
}


async function isRateLimited(
  env,
  request,
  routeKey,
  maxRequests,
  windowSeconds = 60
){

  const nowSeconds =
    Math.floor(
      Date.now() / 1000
    );

  const windowID =
    Math.floor(
      nowSeconds /
      windowSeconds
    );

  const clientKey =
    await rateLimitClientKey(
      request
    );

  const rateKey =
    `${routeKey}:${clientKey}:${windowID}`;

  const expiresAt =
    (windowID + 2) *
    windowSeconds;


  const result =
    await env.QUOTES_DB.prepare(`
      INSERT INTO api_rate_limits (
        rate_key,
        request_count,
        expires_at
      )
      VALUES (?, 1, ?)

      ON CONFLICT(rate_key)
      DO UPDATE SET
        request_count =
          request_count + 1,
        expires_at =
          excluded.expires_at

      RETURNING request_count
    `)
    .bind(
      rateKey,
      expiresAt
    )
    .first();


  /*
    Periodically remove expired counters.
    This does not run on every request.
  */

  if(
    nowSeconds -
    lastRateLimitCleanup >
    3600
  ){

    lastRateLimitCleanup =
      nowSeconds;

    try{

      await env.QUOTES_DB.prepare(`
        DELETE FROM api_rate_limits
        WHERE expires_at < ?
      `)
      .bind(nowSeconds)
      .run();

    }catch(error){

      console.log(
        "Rate-limit cleanup failed:",
        error
      );

    }

  }


  return (
    Number(
      result?.request_count || 0
    ) >
    maxRequests
  );
}

function privateDatasetKey(
  brandId,
  dataset
){

  const brand =
    String(brandId || "STIHL")
      .trim()
      .toUpperCase();

  const datasetName =
    String(dataset || "")
      .trim();

  /*
    Preserve the existing STIHL dataset keys.
    Additional brands receive isolated keys.
  */
  return brand === "STIHL"
    ? datasetName
    : `${brand}::${datasetName}`;
}


async function loadPrivateConfigRows(
  env,
  dataset,
  brandId = "STIHL"
){

  const storageDataset =
    privateDatasetKey(
      brandId,
      dataset
    );

  const row = await env.QUOTES_DB
    .prepare(
      `SELECT payload
       FROM private_config_data
       WHERE dataset = ?`
    )
    .bind(storageDataset)
    .first();

  if(!row || !row.payload){
    throw new Error(
      `Private configurator dataset not found: ${storageDataset}`
    );
  }

  const rows =
    JSON.parse(row.payload);

  if(!Array.isArray(rows)){
    throw new Error(
      `Invalid private configurator dataset: ${storageDataset}`
    );
  }

  return rows;
}

function privatePricingPercent(value){

  const raw =
    onlineMoney(value);

  return raw > 0 && raw < 1
    ? raw * 100
    : raw;
}


function privatePricingCustomerRebate(item){

  if(!item){
    return 0;
  }

  if(
    !onlineDateActive(
      item.RebateStartDate,
      item.RebateEndDate
    )
  ){
    return 0;
  }

  return onlineMoney(
    item.RebateToCustomer ||
    item.CustomerRebateAmount
  );
}


function privatePricingDealerRebate(item){

  if(!item){
    return 0;
  }

  if(
    !onlineDateActive(
      item.RebateStartDate,
      item.RebateEndDate
    )
  ){
    return 0;
  }

  return onlineMoney(
    item.RebateToDealer ||
    item.MfgRebateToDealer
  );
}


function privatePricingUnitPrice(item){

  if(!item){
    return 0;
  }

  const salePrice =
    onlineDateActive(
      item.SaleStartDate,
      item.SaleEndDate
    )
      ? onlineMoney(item.SalePrice)
      : 0;

  return (
    salePrice ||
    onlineMoney(item.MSRP)
  );
}


function privatePricingDealerCost(item){

  if(!item){
    return 0;
  }

  const saleDealerCost =
    onlineDateActive(
      item.SaleStartDate,
      item.SaleEndDate
    )
      ? onlineMoney(item.SaleDealerCost)
      : 0;

  return (
    saleDealerCost ||
    onlineMoney(item.DealerCost)
  );
}


function privatePricingLineDealerCost(item, quantity){

  const qty =
    Math.max(
      Number(quantity) || 1,
      1
    );

  const regularCost =
    privatePricingDealerCost(item);

  const specialCost =
    onlineMoney(
      item.SpecialDealerCost
    );

  const specialAvailable =
    Math.max(
      Number(
        onlineClean(
          item.SpecialCostQty
        )
      ) || 0,
      0
    );

  const specialQty =
    specialCost > 0
      ? Math.min(
          qty,
          specialAvailable
        )
      : 0;

  const regularQty =
    Math.max(
      qty - specialQty,
      0
    );

  return (
    specialCost * specialQty +
    regularCost * regularQty
  );
}


function privatePricingAdvertisingFee(
  item,
  quantity,
  dealerCost
){

  const rawPercent =
    onlineMoney(
      item.AdvertisingFeePercent
    );

  const rate =
    rawPercent > 1
      ? rawPercent / 100
      : rawPercent;

  if(rate > 0){
    return dealerCost * rate;
  }

  return (
    onlineMoney(
      item.AdvertisingFee
    ) *
    Math.max(
      Number(quantity) || 1,
      1
    )
  );
}


async function findPrivatePricingItem(
  env,
  sku,
  brandId = "STIHL"
){

  const wanted =
    onlineClean(sku)
      .toUpperCase();

  if(!wanted){
    return null;
  }

  const logicalDatasets = [
    "products",
    "attachments",
    "accessories",
    "batteries",
    "chargers",
    "parts"
  ];

  const storageDatasets =
    logicalDatasets.map(
      dataset =>
        privateDatasetKey(
          brandId,
          dataset
        )
    );

  const placeholders =
    storageDatasets
      .map(() => "?")
      .join(",");

  const result =
    await env.QUOTES_DB
      .prepare(
        `SELECT dataset, payload
         FROM private_config_data
         WHERE dataset IN (${placeholders})`
      )
      .bind(...storageDatasets)
      .all();

  for(const row of (result.results || [])){

    let items = [];

    try{
      items =
        JSON.parse(
          row.payload || "[]"
        );
    }catch(_error){
      continue;
    }

    if(!Array.isArray(items)){
      continue;
    }

    const item =
      items.find(candidate => {

        const identifiers = [
          candidate.SKU,
          candidate.StihlID,
          candidate.BatteryID,
          candidate.ChargerID
        ];

        return identifiers.some(
          value =>
            onlineClean(value)
              .toUpperCase() ===
            wanted
        );
      });

    if(item){
      return item;
    }
  }

  return null;
}

function privatePricingFinanceGroups(item){

  const brandId =
    onlineClean(
      item?.BrandID ||
      "STIHL"
    ).toUpperCase();

  const columns =
    new Set([
      `Group_ALL_${brandId}`
    ]);

  const values = [
    item.FinancingGroup,
    item.Series,
    item.Category,
    item.SubCategory
  ];

  values.forEach(value => {

    const original =
      onlineClean(value);

    if(!original) return;

    columns.add(
      `Group_${original}`
    );

    const compact =
      original
        .toUpperCase()
        .replace(/[^A-Z0-9]/g, "");

    if(compact){
      columns.add(
        `Group_${compact}`
      );
    }
  });

  const familyValues = [
    item.Model,
    item.Series,
    item.FinancingGroup
  ].map(value =>
    onlineClean(value)
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "")
  );

  familyValues.forEach(value => {

    if(/^RZ1/.test(value)){
      columns.add("Group_RZ100");
    }

    if(/^RZ2/.test(value)){
      columns.add("Group_RZ200");
    }

    if(/^RZ5/.test(value)){
      columns.add("Group_RZ500");
    }

    if(/^RZ7/.test(value)){
      columns.add("Group_RZ700");
    }

    if(/^RZ752/.test(value)){
      columns.add("Group_RZ752");
    }

    if(/^RZ9/.test(value)){
      columns.add("Group_RZ900");
    }

    if(/^AZA/.test(value)){
      columns.add("Group_AZA");
    }

    if(/^RZA/.test(value)){
      columns.add("Group_RZA");
    }

    if(/^RMA/.test(value)){
      columns.add("Group_RMA");
    }

    if(/^RM/.test(value)){
      columns.add("Group_RM");
    }

    if(/^FSA120/.test(value)){
      columns.add("FSA 120");
    }
  });

  const zeroTurn =
    familyValues.some(value =>
      /^RZ[0-9]/.test(value) ||
      /^AZA/.test(value) ||
      /^RZA/.test(value)
    ) ||
    values.some(value =>
      onlineClean(value)
        .toUpperCase()
        .includes("ZERO")
    );

  if(zeroTurn){
    columns.add("Group_ALL_ZTR");
  }

  return [...columns];
}


function privatePricingProgramAllowsRebate(program){

  if(!program){
    return true;
  }

  const value =
    onlineClean(
      program.RebateCompatible ??
      program.RebateEligible
    );

  return value === ""
    ? true
    : onlineTrue(value);
}


function privatePricingFinanceProgramApplies(
  item,
  program
){

  if(!item || !program){
    return false;
  }

  if(
    onlineClean(program.Active) !== "" &&
    !onlineTrue(program.Active)
  ){
    return false;
  }

  if(
    onlineClean(program.Display) !== "" &&
    !onlineTrue(program.Display)
  ){
    return false;
  }

  if(
    !onlineDateActive(
      program.StartDate,
      program.EndDate
    )
  ){
    return false;
  }

  const itemBrand =
    onlineClean(
      item.BrandID ||
      "STIHL"
    ).toUpperCase();

  const programBrand =
    onlineClean(
      program.BrandID
    ).toUpperCase();

    if(
    programBrand &&
    itemBrand &&
    programBrand !== itemBrand
  ){
    return false;
  }

  /*
    Enforce the manufacturer finance-bulletin group.

    Examples:
    ZTR programs apply only to ZTR products.
    CUT programs apply only to CUT products.
    UTV programs apply only to UTV products.
    ALL applies to every product within the brand.
  */
  const programFinanceGroup =
    onlineClean(
      program.FinanceBulletinGroup
    ).toUpperCase();

    let itemFinanceGroup =
    onlineClean(
      item.FinanceBulletinGroup ||
      item.FinancingGroup ||
      item.System
    ).toUpperCase();

  /*
    Convert Yanmar product systems into the
    manufacturer finance-bulletin groups.
  */
  if(itemBrand === "YANMAR"){

    if(
      [
        "SA",
        "YT",
        "YM",
        "SM"
      ].includes(itemFinanceGroup)
    ){
      itemFinanceGroup = "CUT";
    }

    if(
      [
        "BULL",
        "LONGHORN",
        "BRAHMA"
      ].includes(itemFinanceGroup)
    ){
      itemFinanceGroup = "UTV";
    }

    if(itemFinanceGroup === "ZTR"){
      itemFinanceGroup = "ZTR";
    }
  }

  if(
    programFinanceGroup &&
    programFinanceGroup !== "ALL" &&
    (
      !itemFinanceGroup ||
      programFinanceGroup !== itemFinanceGroup
    )
  ){
    return false;
  }

  /*
    Finance eligibility uses either minimum profit
    or maximum dealer fee—not both.

    MinimumProfitAmount greater than zero takes
    priority. When no minimum profit is set, an
    explicitly entered maximum fee controls
    eligibility. A blank maximum fee means no cap.
  */
  const requiredProfit =
    onlineMoney(
      item.MinimumProfitAmount
    );

  const maximumFeeSource =
    [
      item.FinanceMaximumFee,
      item.FinanceMaximumFeePercent,
      item.MaxProgramFeePercent,
      item.MaximumFeePercent
    ].find(value =>
      onlineClean(value) !== ""
    );

  const hasMaximumFee =
    maximumFeeSource !== undefined;

  const maximumAllowedFee =
    hasMaximumFee
      ? privatePricingPercent(
          maximumFeeSource
        )
      : 0;

  const programFee =
    privatePricingPercent(
      program.DealerFeePercent
    );

  /*
    Only enforce the maximum finance fee when
    no minimum-profit requirement is set.
  */
  if(
    requiredProfit <= 0 &&
    hasMaximumFee &&
    programFee > maximumAllowedFee
  ){
    return false;
  }

  const unitPrice =
    privatePricingUnitPrice(item);

  const customerRebate =
    privatePricingCustomerRebate(item);

  const rebateAllowed =
    privatePricingProgramAllowsRebate(
      program
    );

    const eligiblePrice =
    rebateAllowed
      ? Math.max(
          unitPrice - customerRebate,
          0
        )
      : unitPrice;

  /*
    Do not offer a finance program if its dealer fee
    would reduce profit below the product's required
    minimum profit.
  */
  if(requiredProfit > 0){

    const dealerCost =
      privatePricingLineDealerCost(
        item,
        1
      );

    const advertisingFee =
      privatePricingAdvertisingFee(
        item,
        1,
        dealerCost
      );

    const trueDealerCost =
      dealerCost +
      advertisingFee;

    const dealerReimbursement =
      rebateAllowed
        ? privatePricingDealerRebate(item)
        : 0;

    /*
      Finance fee is charged against the
      estimated out-the-door amount, including
      Connecticut sales tax.
    */
    const estimatedOutTheDoor =
      eligiblePrice * 1.0635;

    const paymentFee =
      estimatedOutTheDoor *
      (programFee / 100);

    const netProfit =
      eligiblePrice +
      dealerReimbursement -
      trueDealerCost -
      paymentFee;

    if(netProfit < requiredProfit){
      return false;
    }
  }

  const minimum =
    onlineMoney(program.MinAmount);

  const maximum =
    onlineMoney(program.MaxAmount);

  if(
    minimum > 0 &&
    eligiblePrice < minimum
  ){
    return false;
  }

  if(
    maximum > 0 &&
    eligiblePrice > maximum
  ){
    return false;
  }

  const groups =
    privatePricingFinanceGroups(item);

  const sku =
    onlineClean(item.SKU);

  const model =
    onlineClean(item.Model);

  const applicabilityColumns =
    Object.keys(program)
      .filter(key =>
        key === "AllProducts" ||
        key.startsWith("Group_") ||
        key === sku ||
        key === model
      );

  /*
    A brand-specific program with no group/SKU/model
    columns applies to all eligible products of that
    same brand. Honda currently uses this structure.
  */
  const brandWideDefault =
    programBrand !== "" &&
    programBrand === itemBrand &&
    applicabilityColumns.length === 0;

  return (
    brandWideDefault ||
    onlineTrue(
      program.AllProducts ||
      program[
        `Group_ALL_${itemBrand}`
      ]
    ) ||
    groups.some(
      column =>
        onlineTrue(program[column])
    ) ||
    (
      sku &&
      onlineTrue(program[sku])
    ) ||
    (
      model &&
      onlineTrue(program[model])
    )
  );
}

function privatePricingInternalFreight(
  item,
  quantity
){

  const qty =
    Math.max(Number(quantity) || 1, 1);

  const rateType =
    onlineClean(
      item?.FreightRateType
    ).toUpperCase();

  const enteredAmount =
    onlineMoney(
      item?.FreightAmount
    );

  if(
    rateType === "FIXED" ||
    rateType === "AMOUNT"
  ){
    return enteredAmount * qty;
  }

  if(rateType === "PERCENT"){

    if(enteredAmount > 0){
      return enteredAmount * qty;
    }

    const enteredPercent =
      Number(item?.FreightPercent);

    if(
      !Number.isFinite(enteredPercent) ||
      enteredPercent <= 0
    ){
      return 0;
    }

    const decimalRate =
      enteredPercent <= 1
        ? enteredPercent
        : enteredPercent / 100;

    return (
      privatePricingLineDealerCost(
        item,
        qty
      ) *
      decimalRate
    );
  }

  return 0;
}


async function privatePricingProfitProtectionDown(
  env,
  brandId,
  program,
  cart,
  taxExempt,
  primarySku,
  primaryAutomaticDiscount
){

  if(
    !program ||
    !cart ||
    !Array.isArray(cart.items)
  ){
    return 0;
  }

  const cartItems =
    cart.items
      .filter(entry =>
        entry &&
        onlineClean(entry.sku)
      )
      .slice(0, 50);

  if(!cartItems.length){
    return 0;
  }

  const rebateAllowed =
    privatePricingProgramAllowsRebate(
      program
    );

  let merchandiseSelling = 0;
  let trueDealerCost = 0;
  let dealerReimbursement = 0;
  let requiredProfit = 0;
  let internalFreight = 0;

  for(const entry of cartItems){

    const sku =
      onlineClean(entry.sku);

    const quantity =
      Math.min(
        Math.max(
          Math.floor(
            Number(entry.quantity) || 1
          ),
          1
        ),
        100
      );

    const item =
      await findPrivatePricingItem(
        env,
        sku,
        brandId
      );

    if(!item){
      continue;
    }

    const customerRebate =
      rebateAllowed
        ? privatePricingCustomerRebate(
            item
          )
        : 0;

    let sellingPrice =
      Math.max(
        (
          privatePricingUnitPrice(item) -
          customerRebate
        ) *
        quantity,
        0
      );

    if(
      sku === primarySku &&
      primaryAutomaticDiscount > 0
    ){
      sellingPrice =
        Math.max(
          sellingPrice -
          primaryAutomaticDiscount,
          0
        );
    }

    const dealerCost =
      privatePricingLineDealerCost(
        item,
        quantity
      );

    const advertisingFee =
      privatePricingAdvertisingFee(
        item,
        quantity,
        dealerCost
      );

    merchandiseSelling +=
      sellingPrice;

    trueDealerCost +=
      dealerCost +
      advertisingFee;

    dealerReimbursement +=
      (
        rebateAllowed
          ? privatePricingDealerRebate(item)
          : 0
      ) * quantity;

    requiredProfit +=
      onlineMoney(
        item.MinimumProfitAmount
      ) *
      quantity;

    internalFreight +=
      privatePricingInternalFreight(
        item,
        quantity
      );
  }

  const customerFreight =
    onlineMoney(
      cart.customerFreight
    );

  const neutralCharges =
    onlineMoney(cart.setupAmount) +
    onlineMoney(cart.deliveryAmount) +
    onlineMoney(cart.warrantyAmount);

  const grossProfit =
    merchandiseSelling +
    customerFreight +
    dealerReimbursement -
    trueDealerCost -
    internalFreight;

  const taxableMultiplier =
    taxExempt === true
      ? 1
      : 1.0635;

  const customerTotal =
    (
      merchandiseSelling +
      customerFreight +
      neutralCharges
    ) *
    taxableMultiplier;

  const programFeeRate =
    privatePricingPercent(
      program.DealerFeePercent
    ) / 100;

  if(programFeeRate <= 0){
    return 0;
  }

  const netProfit =
    grossProfit -
    (
      customerTotal *
      programFeeRate
    );

  const shortfall =
    Math.max(
      requiredProfit -
      netProfit,
      0
    );

  if(shortfall <= 0){
    return 0;
  }

  return Math.min(
    Math.ceil(
      (
        shortfall /
        programFeeRate
      ) /
      10
    ) * 10,
    customerTotal
  );
}

async function handleCustomerPricing(
  request,
  env,
  corsHeaders
){

  try{

    const body =
      await request.json();

    const sku =
      onlineClean(body?.sku);

    const brandId =
      onlineClean(
        body?.brandId ||
        "STIHL"
      ).toUpperCase();

    const quantity =
      Math.min(
        Math.max(
          Math.floor(
            Number(body?.quantity) || 1
          ),
          1
        ),
        100
      );

    const paymentMethod =
      onlineClean(
        body?.paymentMethod
      ).toLowerCase();

    if(
      !sku ||
      !normalizeSupportedBrand(brandId) ||
      ![
        "cash",
        "credit",
        "finance",
        "split"
      ].includes(paymentMethod)
    ){
      return Response.json(
        { error:"Invalid pricing request." },
        {
          status:400,
          headers:{
            ...corsHeaders,
            "Cache-Control":"no-store"
          }
        }
      );
    }

    const item =
      await findPrivatePricingItem(
        env,
        sku,
        brandId
      );

    if(!item){
      return Response.json(
        { error:"Item not found." },
        {
          status:404,
          headers:{
            ...corsHeaders,
            "Cache-Control":"no-store"
          }
        }
      );
    }

        let selectedFeePercent = 0;
    let rebateAllowed = true;
    let financeProgramID = "";
    let selectedFinanceProgram = null;
    let financeCashAmount = 0;
    let financeCreditAmount = 0;

    if(paymentMethod === "credit"){
      selectedFeePercent = 3;
    }

     if(paymentMethod === "split"){

      const cashAmount =
        onlineMoney(
          body?.cashAmount
        );

      const creditAmount =
        onlineMoney(
          body?.creditAmount
        );

      const paymentTotal =
        cashAmount +
        creditAmount;

      if(paymentTotal <= 0){

        return Response.json(
          { error:"Invalid split payment." },
          {
            status:400,
            headers:{
              ...corsHeaders,
              "Cache-Control":"no-store"
            }
          }
        );
      }

      selectedFeePercent =
        (
          creditAmount * 3
        ) /
        paymentTotal;
    }

    if(paymentMethod === "finance"){

             /*
        Customer deposits reduce the final amount
        financed, but must not create an additional
        automatic merchandise discount.
      */
      financeCashAmount = 0;
      financeCreditAmount = 0;

      financeProgramID =
        onlineClean(
          body?.financeProgramId
        );

      const financePrograms =
      await loadPrivateConfigRows(
        env,
        "finance-programs",
        brandId
      );

      const program =
        financePrograms.find(
          row =>
            onlineClean(row.ProgramID) ===
            financeProgramID
        );

      if(
        !program ||
        !privatePricingFinanceProgramApplies(
          item,
          program
        )
      ){
        return Response.json(
          {
            error:
              "Selected financing program is not eligible."
          },
          {
            status:400,
            headers:{
              ...corsHeaders,
              "Cache-Control":"no-store"
            }
          }
        );
      }

      selectedFinanceProgram =
        program;

      selectedFeePercent =
        privatePricingPercent(
          program.DealerFeePercent
        );

      rebateAllowed =
        privatePricingProgramAllowsRebate(
          program
        );
    }

    const unitPrice =
      privatePricingUnitPrice(item);

    const unitCustomerRebate =
      rebateAllowed
        ? privatePricingCustomerRebate(item)
        : 0;

    const customerRebate =
      unitCustomerRebate *
      quantity;

    const startingSellingPrice =
      Math.max(
        (unitPrice * quantity) -
        customerRebate,
        0
      );

    const requiredProfit =
      onlineMoney(
        item.MinimumProfitAmount
      ) * quantity;

    let automaticDiscount = 0;

    if(requiredProfit <= 0){

      const maximumFeePercent =
        privatePricingPercent(
          item.FinanceMaximumFee ||
          item.FinanceMaximumFeePercent ||
          item.MaxProgramFeePercent ||
          item.MaximumFeePercent
        );

      const availablePercent =
        Math.max(
          maximumFeePercent -
          selectedFeePercent,
          0
        );

      const calculatedUnitDiscount =
        (
          Math.max(
            unitPrice -
            unitCustomerRebate,
            0
          )
        ) *
        (availablePercent / 100);

      const roundedUnitDiscount =
        calculatedUnitDiscount < 10
          ? 0
          : Math.floor(
              calculatedUnitDiscount / 10
            ) * 10;

      automaticDiscount =
        roundedUnitDiscount *
        quantity;

    }else{

      const dealerCost =
        privatePricingLineDealerCost(
          item,
          quantity
        );

      const advertisingFee =
        privatePricingAdvertisingFee(
          item,
          quantity,
          dealerCost
        );

      const trueDealerCost =
        dealerCost +
        advertisingFee;

      const dealerReimbursement =
        (
          rebateAllowed
            ? privatePricingDealerRebate(item)
            : 0
        ) * quantity;

      const taxableMultiplier =
        body?.taxExempt === true
          ? 1
          : 1.0635;

      /*
        Card processing applies to the customer's complete
        payment, not only the equipment selling price. These
        customer charges are profit-neutral elsewhere because
        they offset their corresponding dealer costs, but their
        card fee must still be reserved before calculating the
        maximum automatic discount.
      */
      const cartPrimarySku =
        onlineClean(body?.cart?.primarySku);

      const includeSharedPaymentCharges =
        !cartPrimarySku ||
        cartPrimarySku === sku;

      const paymentFeeCharges =
        includeSharedPaymentCharges
          ? (
              onlineMoney(body?.cart?.customerFreight) +
              onlineMoney(body?.cart?.setupAmount) +
              onlineMoney(body?.cart?.deliveryAmount) +
              onlineMoney(body?.cart?.warrantyAmount)
            )
          : 0;

      function netProfit(testDiscount){

        const sellingPrice =
          Math.max(
            startingSellingPrice -
            testDiscount,
            0
          );

        let paymentFee = 0;

        if(
          paymentMethod === "finance" &&
          (
            financeCashAmount > 0 ||
            financeCreditAmount > 0
          )
        ){
          /*
            Mixed payment:
            - Card fee applies only to the card deposit.
            - Finance dealer fee applies only to the
              remaining financed balance.
            - Cash deposit carries no payment fee.
          */
          const estimatedCustomerTotal =
            (
              sellingPrice +
              paymentFeeCharges
            ) *
            taxableMultiplier;

          const boundedCashAmount =
            Math.min(
              financeCashAmount,
              estimatedCustomerTotal
            );

          const boundedCreditAmount =
            Math.min(
              financeCreditAmount,
              Math.max(
                estimatedCustomerTotal -
                boundedCashAmount,
                0
              )
            );

          const estimatedFinanceAmount =
            Math.max(
              estimatedCustomerTotal -
              boundedCashAmount -
              boundedCreditAmount,
              0
            );

          paymentFee =
            (
              boundedCreditAmount *
              0.03
            ) +
            (
              estimatedFinanceAmount *
              (
                selectedFeePercent /
                100
              )
            );

        }else{
          paymentFee =
            (
              sellingPrice +
              paymentFeeCharges
            ) *
            taxableMultiplier *
            (
              selectedFeePercent /
              100
            );
        }

        return (
          sellingPrice +
          dealerReimbursement -
          trueDealerCost -
          paymentFee
        );
      }

      let low = 0;
      let high =
        startingSellingPrice;

      let maximumDiscount = 0;

      for(let i = 0; i < 60; i++){

        const testDiscount =
          (low + high) / 2;

        if(
          netProfit(testDiscount) >=
          requiredProfit
        ){
          maximumDiscount =
            testDiscount;

          low =
            testDiscount;
        }else{
          high =
            testDiscount;
        }
      }

      automaticDiscount =
        Math.max(
          Math.floor(
            maximumDiscount / 10
          ) * 10,
          0
        );
    }

    const customerLinePrice =
      Math.max(
        startingSellingPrice -
        automaticDiscount,
        0
      );

    const roundMoney =
      value =>
        Math.round(
          (Number(value) + Number.EPSILON) *
          100
        ) / 100;

    const profitProtectionDown =
      (
        paymentMethod === "finance" &&
        selectedFinanceProgram
      )
        ? await privatePricingProfitProtectionDown(
            env,
            brandId,
            selectedFinanceProgram,
            body?.cart,
            body?.taxExempt === true,
            onlineClean(
              body?.cart?.primarySku ||
              sku
            ),
            automaticDiscount
          )
        : 0;

    return Response.json(
      {
        ok:true,
        sku,
        quantity,
        paymentMethod,
        financeProgramId:
          financeProgramID || null,

        baseUnitPrice:
          roundMoney(unitPrice),

        customerRebate:
          roundMoney(customerRebate),

        automaticDiscount:
          roundMoney(automaticDiscount),

        profitProtectionDown:
          roundMoney(
            profitProtectionDown
          ),

          customerLinePrice:
          roundMoney(customerLinePrice),

        customerUnitPrice:
          roundMoney(
            customerLinePrice /
            quantity
          )
      },
      {
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );

  }catch(error){

    console.error(
      "Customer pricing failed:",
      error
    );

    return Response.json(
      {
        error:
          "Unable to calculate customer pricing."
      },
      {
        status:500,
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );
  }
}

async function handleCustomerFinancePrograms(
  request,
  env,
  corsHeaders
){

  try{

    const body =
      await request.json();

     const sku =
      onlineClean(body?.sku);

    const brandId =
      onlineClean(
        body?.brandId ||
        "STIHL"
      ).toUpperCase();

    if(
      !sku ||
      !normalizeSupportedBrand(brandId)
    ){

      return Response.json(
        { error:"SKU is required." },
        {
          status:400,
          headers:{
            ...corsHeaders,
            "Cache-Control":"no-store"
          }
        }
      );
    }

    const item =
      await findPrivatePricingItem(
        env,
        sku,
        brandId
      );

    if(!item){

      return Response.json(
        { error:"Item not found." },
        {
          status:404,
          headers:{
            ...corsHeaders,
            "Cache-Control":"no-store"
          }
        }
      );
    }

    const financePrograms =
        await loadPrivateConfigRows(
          env,
          "finance-programs",
          brandId
        );

    const programs =
      financePrograms
        .filter(program =>
          privatePricingFinanceProgramApplies(
            item,
            program
          )
        )
        .sort((a,b) =>
          onlineMoney(a.APR) -
          onlineMoney(b.APR) ||
          Number(
            onlineClean(a.TermMonths)
          ) -
          Number(
            onlineClean(b.TermMonths)
          )
        )
        .map(program => ({
          ProgramID:
            onlineClean(program.ProgramID),

          ProgramName:
            onlineClean(program.ProgramName),

          APR:
            onlineMoney(program.APR),

          TermMonths:
            Number(
              onlineClean(program.TermMonths)
            ) || 0,

          CreditScoreMin:
            onlineMoney(
              program.CreditScoreMin
            ),

          CreditScoreMax:
            onlineMoney(
              program.CreditScoreMax
            ),

          CustomerOriginationFee:
            onlineMoney(
              program.CustomerOriginationFee
            ),

          MinAmount:
            onlineMoney(program.MinAmount),

          MaxAmount:
            onlineMoney(program.MaxAmount),

          MinDownAmount:
            onlineMoney(
              program.MinDownAmount
            ),

          MinDownPercent:
            onlineMoney(
              program.MinDownPercent
            ),

          RebateCompatible:
            onlineClean(
              program.RebateCompatible
            ),

          StartDate:
            onlineClean(program.StartDate),

          EndDate:
            onlineClean(program.EndDate),

          BrandID:
            onlineClean(program.BrandID),

          Lender:
            onlineClean(program.Lender),

          ApplicationURL:
            onlineClean(
              program.ApplicationURL
            )
        }));

    return Response.json(
      {
        ok:true,
        sku,
        programs
      },
      {
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );

  }catch(error){

    console.error(
      "Customer finance programs failed:",
      error
    );

    return Response.json(
      {
        error:
          "Unable to load financing programs."
      },
      {
        status:500,
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );
  }
}

export default {
  async fetch(request, env) {
    const corsHeaders = browserCorsHeaders(request);

    if (request.method === "OPTIONS") {
      const origin = String(request.headers.get("Origin") || "");
      if(origin && !ALLOWED_BROWSER_ORIGINS.has(origin)){
        return new Response(null, { status:403, headers:{ "Vary":"Origin" } });
      }
      return new Response(null, { headers: corsHeaders });
}

const url = new URL(request.url);

if(request.method === "POST"){

    /*
  ============================================================
  PUBLIC API RATE LIMITS
  Protect expensive/public Buy Online endpoints from abuse.
  ============================================================
*/



  let maxRequests = 0;

  if(
    url.pathname ===
    "/online-order"
  ){
    maxRequests = 5;
  }

  if(
    url.pathname ===
    "/quote-lead"
  ){
    maxRequests = 5;
  }

  if(
    url.pathname ===
    "/shipping-rate"
  ){
    maxRequests = 30;
  }

  if(
    url.pathname ===
    "/dealer-data"
  ){
    maxRequests = 10;
  }

   if(
    url.pathname ===
    "/customer-pricing"
  ){
    maxRequests = 60;
  }

  if(
    url.pathname ===
    "/customer-finance-programs"
  ){
    maxRequests = 60;
  }

  if(maxRequests > 0){

    const limited =
      await isRateLimited(
        env,
        request,
        url.pathname,
        maxRequests,
        60
      );


    if(limited){

      console.log(
        `Rate limit exceeded: ${url.pathname}`
      );

      return Response.json(
        {
          error:
            "Too many requests. Please wait a moment and try again."
        },
        {
          status:429,

          headers:{
            ...corsHeaders,
            "Retry-After":"60"
          }
        }
      );

    }

  }

}

if(
  url.pathname === "/customer-finance-programs" &&
  request.method === "POST"
){
  return handleCustomerFinancePrograms(
    request,
    env,
    corsHeaders
  );
}

if(
  url.pathname === "/customer-pricing" &&
  request.method === "POST"
){
  return handleCustomerPricing(
    request,
    env,
    corsHeaders
  );
}

if(url.pathname === "/dealer-data" && request.method === "POST"){
      try{

        const body =
          await request.json()
            .catch(() => ({}));

        const brandId =
          String(body?.brandId || "STIHL")
            .trim()
            .toUpperCase();

        if(!normalizeSupportedBrand(brandId)){
          return Response.json(
            {
              error:
                "Invalid dealer-data brand."
            },
            {
              status:400,
              headers:{
                ...corsHeaders,
                "Cache-Control":"no-store"
              }
            }
          );
        }

        /*
          Allow either the dealer password or an existing
          signed, brand-specific dealer session. This lets a
          same-tab refresh restore Dealer Mode without storing
          or resending the password.
        */
        const sessionAuthorized =
          await verifyDealerSessionToken(
            request,
            env,
            brandId
          );

        if(!sessionAuthorized){
          const authResponse =
            dealerAuthorizationResponse(
              request,
              env,
              corsHeaders
            );

          if(authResponse){
            return authResponse;
          }
        }

        const brandPrefix =
          `${brandId}::`;

        const result =
          brandId === "STIHL"
            ? await env.QUOTES_DB
                .prepare(
                  `SELECT dataset, payload, updated_at
                   FROM private_config_data
                   WHERE dataset NOT LIKE '%::%'
                   ORDER BY dataset`
                )
                .all()
            : await env.QUOTES_DB
                .prepare(
                  `SELECT dataset, payload, updated_at
                   FROM private_config_data
                   WHERE dataset LIKE ?
                   ORDER BY dataset`
                )
                .bind(`${brandPrefix}%`)
                .all();

        const data = {};

        for(const row of (result.results || [])){
          try{

            const publicDatasetName =
              brandId === "STIHL"
                ? row.dataset
                : row.dataset.slice(
                    brandPrefix.length
                  );

            data[publicDatasetName] = {
              payload:
                JSON.parse(row.payload),

              updated_at:
                row.updated_at
            };

          }catch(_error){
            console.error(
              `Invalid private configurator JSON: ${row.dataset}`
            );
          }
        }

        const dealerSessionToken =
          await createDealerSessionToken(
            env,
            brandId
          );

        return Response.json(
          {
            ok:true,
            data,
            dealerSessionToken
          },
          {
            headers:{
              ...corsHeaders,
              "Cache-Control":"no-store"
            }
          }
        );

      }catch(error){
        console.error(
          "Dealer data read failed:",
          error
        );

        return Response.json(
          {
            error:"Unable to load dealer data."
          },
          {
            status:500,
            headers:{
              ...corsHeaders,
              "Cache-Control":"no-store"
            }
          }
        );
      }
    }
    
    if(
  url.pathname === "/dealer-quote-state" &&
  request.method === "POST"
){
  return saveDealerQuoteState(
    request,
    env,
    corsHeaders
  );
}

    const staffPaths = new Set([
      "/dashboard",
      "/quotes",
      "/quote-status",
      "/quote-note",
      "/quote-followup",
      "/quote-payment",
      "/quote-payment-void",
      "/quote-customer",
"/quote-customer-note",
"/online-orders",
      "/online-order-update",
      "/config-private-sync"
    ]);

    if(staffPaths.has(url.pathname)){
      const authResponse = staffAuthorizationResponse(request, env);
      if(authResponse) return authResponse;
    }

    if (url.pathname === "/config-private-sync" && request.method === "POST") {
  try {
    const body = await request.json();

    const allowedDatasets = new Set([
      "products",
      "attachments",
      "accessories",
      "batteries",
      "chargers",
      "parts",
      "promotions",
      "finance-programs",
      "payment-options",
      "bid-fleet-programs",
      "freight-rules",
      "dealer-rules"
    ]);

    const dataset =
      String(body?.dataset || "")
        .trim();

    const brandId =
      String(body?.brandId || "STIHL")
        .trim()
        .toUpperCase();

    if(!normalizeSupportedBrand(brandId)){
      return Response.json(
        {
          error:
            "Invalid private dataset brand."
        },
        {
          status:400,
          headers:{
            ...corsHeaders,
            "Cache-Control":"no-store"
          }
        }
      );
    }

    const storageDataset =
      privateDatasetKey(
        brandId,
        dataset
      );

    if (!allowedDatasets.has(dataset)) {
      return Response.json(
        { error:"Invalid private dataset." },
        {
          status:400,
          headers:{
            ...corsHeaders,
            "Cache-Control":"no-store"
          }
        }
      );
    }

    if (!Object.prototype.hasOwnProperty.call(body, "payload")) {
      return Response.json(
        { error:"Private dataset payload is required." },
        {
          status:400,
          headers:{
            ...corsHeaders,
            "Cache-Control":"no-store"
          }
        }
      );
    }

    const payload = JSON.stringify(body.payload);

    if (payload.length > 4000000) {
      return Response.json(
        { error:"Private dataset is too large." },
        {
          status:413,
          headers:{
            ...corsHeaders,
            "Cache-Control":"no-store"
          }
        }
      );
    }

    await env.QUOTES_DB
      .prepare(
        `INSERT INTO private_config_data
           (dataset, payload, updated_at)
         VALUES (?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(dataset)
         DO UPDATE SET
           payload = excluded.payload,
           updated_at = CURRENT_TIMESTAMP`
      )
      .bind(storageDataset, payload)
      .run();

    return Response.json(
      {
         ok:true,
        brandId,
        dataset,
        storageDataset
      },
      {
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );

  } catch(error) {
    console.error("Private config sync failed:", error);

    return Response.json(
      { error:"Unable to sync private configurator data." },
      {
        status:500,
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );
  }
}

if (url.pathname === "/quote-status" && request.method === "POST") {
  return updateQuoteStatus(request, env, corsHeaders);
}

if (url.pathname === "/quote-note" && request.method === "POST") {
  return addQuoteNote(request, env, corsHeaders);
}

if (url.pathname === "/quote-followup" && request.method === "POST") {
  return updateQuoteFollowUp(request, env, corsHeaders);
}

if (url.pathname === "/quote-payment" && request.method === "POST") {
  return recordQuotePayment(request, env, corsHeaders);
}

if (url.pathname === "/quote-payment-void" && request.method === "POST") {
  return voidQuotePayment(request, env, corsHeaders);
}

if (url.pathname === "/quote-customer" && request.method === "POST") {
  return updateQuoteCustomer(request, env, corsHeaders);
}

if (
  url.pathname === "/quote-customer-note" &&
  request.method === "POST"
) {
  return updateQuoteCustomerNote(
    request,
    env,
    corsHeaders
  );
}

if (url.pathname === "/dashboard" && request.method === "GET") {
  return handleDashboard(env);
}

if (url.pathname === "/online-orders" && request.method === "GET") {
  return handleOnlineOrders(env, request);
}

if (url.pathname === "/online-order-update" && request.method === "POST") {
  return updateOnlineOrder(request, env, corsHeaders);
}

if (url.pathname === "/shipping-rate" && request.method === "POST") {
  return handleShippingRate(request, env, corsHeaders);
}

if (url.pathname === "/online-order" && request.method === "POST") {
  return handleOnlineOrder(request, env, corsHeaders);
}

    if (url.pathname === "/quotes" && request.method === "GET") {
  return handleQuoteManager(env, request);
}

if (request.method !== "POST") {
  return Response.json(
    { error: "Method not allowed" },
    { status: 405, headers: corsHeaders }
  );
}

if (url.pathname !== "/quote-lead") {
  return Response.json(
    { error: "Not found" },
    { status: 404, headers: corsHeaders }
  );
}

        const quoteContentType =
      String(
        request.headers.get(
          "Content-Type"
        ) || ""
      )
        .split(";")[0]
        .trim()
        .toLowerCase();

    if(quoteContentType !== "application/json"){
      return Response.json(
        {
          error:
            "Content-Type must be application/json."
        },
        {
          status: 415,
          headers: corsHeaders
        }
      );
    }

    const maximumQuoteRequestBytes =
      30 * 1024 * 1024;

    const statedQuoteRequestBytes =
      Number(
        request.headers.get(
          "Content-Length"
        ) || 0
      );

    if(
      statedQuoteRequestBytes >
      maximumQuoteRequestBytes
    ){
      return Response.json(
        {
          error:
            "Quote request is too large."
        },
        {
          status: 413,
          headers: corsHeaders
        }
      );
    }

    const rawQuote =
      await request.text();

    const actualQuoteRequestBytes =
      new TextEncoder()
        .encode(rawQuote)
        .byteLength;

    if(
      actualQuoteRequestBytes >
      maximumQuoteRequestBytes
    ){
      return Response.json(
        {
          error:
            "Quote request is too large."
        },
        {
          status: 413,
          headers: corsHeaders
        }
      );
    }

    let quote;

    try{
      quote =
        JSON.parse(rawQuote);
    }catch(_error){
      return Response.json(
        {
          error:
            "Quote request contains invalid JSON."
        },
        {
          status: 400,
          headers: corsHeaders
        }
      );
    }

    if(
      !quote ||
      typeof quote !== "object" ||
      Array.isArray(quote)
    ){
      return Response.json(
        {
          error:
            "Quote request must contain an object."
        },
        {
          status: 400,
          headers: corsHeaders
        }
      );
    }

    const quoteTradePhotos =
      Array.isArray(quote?.trade?.photos)
        ? quote.trade.photos
        : [];

    if(quoteTradePhotos.length > 8){
      return Response.json(
        {
          error:
            "A maximum of 8 trade-in photos is allowed."
        },
        {
          status: 400,
          headers: corsHeaders
        }
      );
    }

    let totalTradePhotoBytes = 0;

    for(const photo of quoteTradePhotos){
      const filename =
        String(photo?.filename || "");

      const content =
        String(photo?.content || "");

      if(
        !filename ||
        filename.length > 160 ||
        !content ||
        content.length % 4 !== 0 ||
        !/^[A-Za-z0-9+/]*={0,2}$/.test(content)
      ){
        return Response.json(
          {
            error:
              "A trade-in photo is invalid."
          },
          {
            status: 400,
            headers: corsHeaders
          }
        );
      }

      const padding =
        content.endsWith("==")
          ? 2
          : content.endsWith("=")
            ? 1
            : 0;

      const photoBytes =
        Math.floor(
          content.length * 3 / 4
        ) - padding;

      if(photoBytes > 5 * 1024 * 1024){
        return Response.json(
          {
            error:
              "Each trade-in photo must be 5 MB or smaller."
          },
          {
            status: 413,
            headers: corsHeaders
          }
        );
      }

      totalTradePhotoBytes += photoBytes;
    }

    if(totalTradePhotoBytes > 20 * 1024 * 1024){
      return Response.json(
        {
          error:
            "Trade-in photos must total 20 MB or less."
        },
        {
          status: 413,
          headers: corsHeaders
        }
      );
    }
    const configurator = quote.configurator || "Configurator";
        const quoteNumber =
      String(
        quote.quoteNumber || ""
      ).trim();

    if(
      !/^[A-Za-z0-9_-]{1,80}$/.test(
        quoteNumber
      )
    ){
      return Response.json(
        {
          error:
            "Quote number is invalid."
        },
        {
          status: 400,
          headers: corsHeaders
        }
      );
    }
    const action = quote.action || "Print / Save PDF";
    const customer = quote.customer || "No customer entered";
    const total = quote.total || "No total";
    const totalNumber = String(total).replace(/[$,]/g, "");

    const depositLink =
      `https://www.westendpower.com/payment-request-tool?` +
      `quote=${encodeURIComponent(quoteNumber)}` +
      `&customer=${encodeURIComponent(customer)}` +
      `&email=${encodeURIComponent(quote.email || "")}` +
      `&amount=500` +
      `&type=deposit` +
      `&product=${encodeURIComponent(quote.selectedTool || configurator)}`;

    const fullLink =
      `https://www.westendpower.com/payment-request-tool?` +
      `quote=${encodeURIComponent(quoteNumber)}` +
      `&customer=${encodeURIComponent(customer)}` +
      `&email=${encodeURIComponent(quote.email || "")}` +
      `&amount=${encodeURIComponent(totalNumber)}` +
      `&type=full` +
      `&product=${encodeURIComponent(quote.selectedTool || configurator)}`;

    const itemsHtml = Array.isArray(quote.items)
      ? quote.items.map(item => `
          <tr>
            <td>${escapeHtml(String(item.qty || ""))}</td>
            <td>${escapeHtml(String(item.name || ""))}</td>
            <td>${escapeHtml(String(item.price || ""))}</td>
            <td>${escapeHtml(String(item.lineTotal || ""))}</td>
          </tr>
        `).join("")
      : "";

      const trade = quote.trade || null;

      const tradePhotoThumbs =
  trade && Array.isArray(trade.photos) && trade.photos.length
    ? `
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;">
        ${trade.photos.slice(0, 4).map(photo => `
          <img src="${escapeHtml(photo.dataUrl || "")}"
               style="width:120px;height:90px;object-fit:cover;border:1px solid #ddd;border-radius:6px;">
        `).join("")}
      </div>
    `
    : "";

const tradeHtml = trade
  ? `
    <h3>Trade-In</h3>

    ${[trade.year, trade.make, trade.model].filter(Boolean).length ? `
      <p><strong>Trade:</strong> ${escapeHtml([trade.year, trade.make, trade.model].filter(Boolean).join(" "))}</p>
    ` : ""}

    ${trade.hours ? `<p><strong>Hours:</strong> ${escapeHtml(trade.hours)}</p>` : ""}
    ${trade.condition ? `<p><strong>Condition:</strong> ${escapeHtml(trade.condition)}</p>` : ""}
    ${trade.serial ? `<p><strong>Serial Number:</strong> ${escapeHtml(trade.serial)}</p>` : ""}
    ${trade.allowance ? `<p><strong>Trade Allowance:</strong> ${escapeHtml("$" + Number(trade.allowance).toLocaleString())}</p>` : ""}
    ${trade.photoCount ? `<p><strong>Photos Uploaded:</strong> ${escapeHtml(trade.photoCount)}</p>` : ""}
    ${trade.notes ? `<p><strong>Trade Notes:</strong> ${escapeHtml(trade.notes)}</p>` : ""}

${tradePhotoThumbs}
  `
  : "";

    const html = `
      <h2>${escapeHtml(configurator)} Quote Lead</h2>

      <p>
        <strong>Quote Number:</strong>
        ${escapeHtml(quoteNumber)}
      </p>

      <p><strong>Action:</strong> ${escapeHtml(action)}</p>
      <p><strong>Prepared By:</strong> ${escapeHtml(quote.salesperson || "")}</p>
      <p><strong>Customer:</strong> ${escapeHtml(customer)}</p>
      <p><strong>Business:</strong> ${escapeHtml(quote.business || "")}</p>
      <p><strong>Phone:</strong> ${escapeHtml(quote.phone || "")}</p>
      <p><strong>Alt Phone:</strong> ${escapeHtml(quote.altPhone || "")}</p>
      <p><strong>Email:</strong> ${escapeHtml(quote.email || "")}</p>
      <p><strong>Address:</strong> ${escapeHtml(quote.address || "")}</p>
      <p><strong>Delivery / Pickup:</strong> ${escapeHtml(quote.delivery || "")}</p>
      <p><strong>Payment:</strong> ${escapeHtml(quote.payment || "")}</p>
      <p><strong>Selected Tool:</strong> ${escapeHtml(quote.selectedTool || "")}</p>

      <h3>Quote Items</h3>
      <table border="1" cellpadding="6" cellspacing="0">
        <tr>
          <th>Qty</th>
          <th>Item</th>
          <th>Unit Price</th>
          <th>Line Total</th>
        </tr>
        ${itemsHtml}
      </table>

      <h3>Totals</h3>
<p><strong>Subtotal:</strong> ${escapeHtml(quote.subtotal || "")}</p>
<p><strong>Tax:</strong> ${escapeHtml(quote.tax || "")}</p>
<p><strong>Total:</strong> ${escapeHtml(total)}</p>

${tradeHtml}

<h3>Payment Requests</h3>

      <p>
        <a href="${depositLink}" style="
          display:inline-block;
          background:#111;
          color:#fff;
          padding:10px 14px;
          text-decoration:none;
          border-radius:6px;
          font-weight:bold;
          margin-right:8px;
        ">
          Request Deposit
        </a>

        <a href="${fullLink}" style="
          display:inline-block;
          background:#f37021;
          color:#111;
          padding:10px 14px;
          text-decoration:none;
          border-radius:6px;
          font-weight:bold;
        ">
          Request Remaining Balance
        </a>
      </p>

      <p style="font-size:12px;color:#666;">
        These links open the internal West End Power payment request tool with the quote information pre-filled.
      </p>

      <h3>Notes</h3>
      <p>${escapeHtml(quote.notes || "")}</p>
    `;

    const attachments =
  trade && Array.isArray(trade.photos)
    ? trade.photos
        .filter(p => p && p.filename && p.content)
        .map(p => ({
          filename: p.filename,
          content: p.content
        }))
    : [];

        const quoteForStorage = {
      ...quote,

      trade:
        trade
          ? {
              ...trade,

              photos:
                Array.isArray(trade.photos)
                  ? trade.photos.map(photo => ({
                      filename:
                        String(
                          photo?.filename ||
                          ""
                        )
                    }))
                  : []
            }
          : null
    };

    try {
  await env.QUOTES_DB.prepare(`
    INSERT INTO quotes (
      quote_number,
      created_at,
      configurator,
      source,
      action,
      salesperson,
      customer,
      business,
      phone,
      alt_phone,
      email,
      address,
      delivery,
      payment,
      selected_tool,
      subtotal,
      tax,
      total,
      status,
      payload_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    quoteNumber,
    new Date().toISOString(),
    configurator,
    quote.source || "",
    action,
    quote.salesperson || "",
    customer,
    quote.business || "",
    quote.phone || "",
    quote.altPhone || "",
    quote.email || "",
    quote.address || "",
    quote.delivery || "",
    quote.payment || "",
    quote.selectedTool || "",
    quote.subtotal || "",
    quote.tax || "",
    total,
    "Open",
    JSON.stringify(quoteForStorage)
  ).run();
} catch (dbError) {
  console.log(
    "Quote database save failed:",
    dbError
  );

  const databaseMessage =
    String(dbError?.message || "");

  if(
    databaseMessage
      .toLowerCase()
      .includes("unique constraint")
  ){
    return Response.json(
      {
        error:
          "This quote number already exists."
      },
      {
        status: 409,
        headers: corsHeaders
      }
    );
  }

  return Response.json(
    {
      error:
        "Unable to save the quote."
    },
    {
      status: 500,
      headers: corsHeaders
    }
  );
}

    const resendResponse = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "West End Power <sales@westendpower.com>",
        to: ["sales@westendpower.com"],
        subject: `${quoteNumber} - ${configurator} Quote Lead - ${customer} - ${total}`,
        html,
        attachments
      })
    });

    const data = await resendResponse.json();

        if(!resendResponse.ok){
      console.log(
        "Quote email delivery failed:",
        data
      );

      return Response.json(
        {
          error:
            "Unable to deliver the quote email."
        },
        {
          status: 500,
          headers: corsHeaders
        }
      );
    }

    return Response.json(
      { ok: true, data },
      { headers: corsHeaders }
    );
  }
};

async function getUPSToken(env) {

  const now = Date.now();

  if(
    upsTokenCache.token &&
    upsTokenCache.expiresAt > now + 60000
  ){
    return upsTokenCache.token;
  }

  const credentials =
    btoa(
      `${env.UPS_CLIENT_ID}:${env.UPS_CLIENT_SECRET}`
    );

  const response = await fetch(
    "https://onlinetools.ups.com/security/v1/oauth/token",
    {
      method: "POST",
      headers: {
        "Authorization": `Basic ${credentials}`,
        "Content-Type":
          "application/x-www-form-urlencoded",
        "x-merchant-id":
          env.UPS_ACCOUNT_NUMBER
      },
      body:
        "grant_type=client_credentials"
    }
  );

  const data = await response.json();

  if(!response.ok || !data.access_token){
    console.log(
      "UPS OAuth failed:",
      response.status,
      data
    );

    throw new Error(
      "Unable to authenticate with UPS."
    );
  }

  const expiresIn =
    Number(data.expires_in) || 3600;

  upsTokenCache = {
    token: data.access_token,
    expiresAt:
      now + (expiresIn * 1000)
  };

  return data.access_token;
}


async function handleShippingRate(
  request,
  env,
  corsHeaders
){

  try{

    const input =
      await request.json();

    const destinationZIP =
      String(
        input.destinationZIP || ""
      ).trim();

    const weight =
      Number(input.weight);

    const length =
      Number(input.length);

    const width =
      Number(input.width);

    const height =
      Number(input.height);

    if(!/^\d{5}$/.test(destinationZIP)){
      return Response.json(
        {
          error:
            "Please enter a valid 5-digit ZIP code."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }

    if(
      !weight ||
      !length ||
      !width ||
      !height ||
      weight <= 0 ||
      length <= 0 ||
      width <= 0 ||
      height <= 0
    ){
      return Response.json(
        {
          error:
            "Valid package weight and dimensions are required."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }

    const token =
      await getUPSToken(env);

      const pickupNow =
  new Date();

const pickupParts =
  new Intl.DateTimeFormat(
    "en-US",
    {
      timeZone:"America/New_York",
      year:"numeric",
      month:"2-digit",
      day:"2-digit"
    }
  )
  .formatToParts(pickupNow);

const pickupPart =
  type =>
    pickupParts.find(
      part => part.type === type
    )?.value || "";

const pickupDate =
  pickupPart("year") +
  pickupPart("month") +
  pickupPart("day");

const pickupTime =
  "1200";

    const upsRequest = {
      RateRequest: {

        Request: {
          TransactionReference: {
            CustomerContext:
              "West End Power Online Shipping"
          }
        },

        Shipment: {

          Shipper: {
            Name:
              "West End Power Equipment",
            ShipperNumber:
              env.UPS_ACCOUNT_NUMBER,
            Address: {
              City:"New Milford",
StateProvinceCode:"CT",
PostalCode:"06776",
CountryCode:"US"
            }
          },

          ShipFrom: {
            Name:
              "West End Power Equipment",
            Address: {
              City:"New Milford",
StateProvinceCode:"CT",
PostalCode:"06776",
CountryCode:"US"
            }
          },

          ShipTo: {
            Name:"Customer",
            Address: {
              PostalCode:
                destinationZIP,
              CountryCode:"US",

              /*
                Conservative for customer-facing
                estimates. This includes the UPS
                residential classification.
              */
              ResidentialAddressIndicator:"Y"
            }
          },

          PaymentDetails: {
            ShipmentCharge: [
              {
                Type:"01",
                BillShipper: {
                  AccountNumber:
                    env.UPS_ACCOUNT_NUMBER
                }
              }
            ]
          },

          Service: {
            Code:"03",
            Description:"Ground"
          },

          DeliveryTimeInformation: {
  PackageBillType:"03",
  Pickup: {
    Date:pickupDate,
    Time:pickupTime
  }
},

          NumOfPieces:"1",

          Package: {
            PackagingType: {
              Code:"02",
              Description:"Package"
            },

            Dimensions: {
              UnitOfMeasurement: {
                Code:"IN",
                Description:"Inches"
              },
              Length:String(length),
              Width:String(width),
              Height:String(height)
            },

            PackageWeight: {
              UnitOfMeasurement: {
                Code:"LBS",
                Description:"Pounds"
              },
              Weight:String(weight)
            }
          }
        }
      }
    };

    const rateResponse =
      await fetch(
        "https://onlinetools.ups.com/api/rating/v2409/Rate?additionalinfo=timeintransit",
        {
          method:"POST",
          headers:{
            "Authorization":
              `Bearer ${token}`,
            "Content-Type":
              "application/json",
            "transId":
              crypto.randomUUID(),
            "transactionSrc":
              "WestEndPower"
          },
          body:
            JSON.stringify(upsRequest)
        }
      );

    const rateData =
      await rateResponse.json();

    if(!rateResponse.ok){
      console.log(
        "UPS Rating failed:",
        rateResponse.status,
        rateData
      );

      return Response.json(
        {
          error:
            "UPS rate could not be calculated.",
          details:
            rateData
        },
        {
          status:502,
          headers:corsHeaders
        }
      );
    }

    let ratedShipment =
      rateData
        ?.RateResponse
        ?.RatedShipment;

    if(Array.isArray(ratedShipment)){
      ratedShipment =
        ratedShipment[0];
    }

    /*
      Use West End's negotiated UPS rate
      when UPS supplies one. Otherwise use
      the standard returned Ground charge.
    */
    const amount =
      Number(
        ratedShipment
          ?.NegotiatedRateCharges
          ?.TotalCharge
          ?.MonetaryValue
        ||
        ratedShipment
          ?.TotalCharges
          ?.MonetaryValue
        ||
        0
      );

      const timeInTransit =
  ratedShipment
    ?.TimeInTransit ||
  null;

let serviceSummary =
  timeInTransit
    ?.ServiceSummary ||
  null;

if(Array.isArray(serviceSummary)){
  serviceSummary =
    serviceSummary[0] || null;
}

const estimatedArrival =
  serviceSummary
    ?.EstimatedArrival ||
  null;

const businessDaysInTransit =
  Number(
    estimatedArrival
      ?.BusinessDaysInTransit
  ) || null;

const estimatedArrivalDate =
  String(
    estimatedArrival
      ?.Arrival
      ?.Date ||
    ""
  );

    if(!amount){
      return Response.json(
        {
          error:
            "UPS returned no usable Ground rate."
        },
        {
          status:502,
          headers:corsHeaders
        }
      );
    }

    return Response.json(
  {
    ok:true,
    carrier:"UPS",
    service:"UPS Ground",
    amount,
    originZIP:"06776",
    destinationZIP,
    businessDaysInTransit,
    estimatedArrivalDate,
    transit:timeInTransit
  },
      {
        headers:corsHeaders
      }
    );

  }catch(error){

    console.log(
      "Shipping rate error:",
      error
    );

    return Response.json(
      {
        error:
          error?.message ||
          "Shipping rate calculation failed."
      },
      {
        status:500,
        headers:corsHeaders
      }
    );
  }
}

async function ensureOnlineOrdersTable(env){

  await env.QUOTES_DB.prepare(`
    CREATE TABLE IF NOT EXISTS online_orders (

      id INTEGER PRIMARY KEY AUTOINCREMENT,

      order_number TEXT UNIQUE,
      checkout_token TEXT,

      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,

      status TEXT NOT NULL,
      payment_status TEXT NOT NULL,

      first_name TEXT,
      last_name TEXT,
      address_line1 TEXT,
      address_line2 TEXT,
      city TEXT,
      state TEXT,
      zip TEXT,
      phone TEXT,
      email TEXT,

      sku TEXT,
      product_name TEXT,
      quantity INTEGER,

      item_price REAL,

      fulfillment TEXT,
      pickup_location TEXT,

      carrier TEXT,
      service TEXT,
      shipping_amount REAL,
      shipping_zip TEXT,

      subtotal REAL,
      tax REAL,
      total REAL,

      estimated_transit_days INTEGER,

      terms_version TEXT,
      terms_text TEXT,
      terms_accepted INTEGER,
      terms_accepted_at TEXT,

      stripe_session_id TEXT,
      stripe_payment_intent TEXT,

      paid_at TEXT,
      paid_email_sent_at TEXT,

      tracking_number TEXT,
      internal_notes TEXT,

      payload_json TEXT
    )
  `).run();

  const columns = await env.QUOTES_DB.prepare(
    "PRAGMA table_info(online_orders)"
  ).all();

  const hasCheckoutToken = (columns.results || []).some(
    column => String(column.name || "") === "checkout_token"
  );

  if(!hasCheckoutToken){
    await env.QUOTES_DB.prepare(
      "ALTER TABLE online_orders ADD COLUMN checkout_token TEXT"
    ).run();
  }

}


function onlineOrderDateCode(){

  const parts =
    new Intl.DateTimeFormat(
      "en-US",
      {
        timeZone:"America/New_York",
        year:"numeric",
        month:"2-digit",
        day:"2-digit"
      }
    )
    .formatToParts(
      new Date()
    );

  const part =
    type =>
      parts.find(
        item => item.type === type
      )?.value || "";

  return (
    part("year") +
    part("month") +
    part("day")
  );
}

/*
  ============================================================
  TRUSTED ONLINE ORDER PRODUCT DATA
  Server-side source of truth for Buy Online orders.
  ============================================================
*/

const ONLINE_PRODUCTS_CSV =
  "https://westendpower.github.io/stihl-battery-configurator/data/products.csv";


function onlineClean(value){
  return String(value ?? "").trim();
}


function onlineTrue(value){

  return [
    "T",
    "TRUE",
    "YES",
    "Y",
    "1",
    "X"
  ].includes(
    onlineClean(value).toUpperCase()
  );
}


function onlineMoney(value){

  const number =
    Number(
      onlineClean(value)
        .replace(/\$/g, "")
        .replace(/,/g, "")
    );

  return Number.isFinite(number)
    ? number
    : 0;
}


function parseOnlineCSV(text){

  const rows = [];

  let row = [];
  let field = "";
  let quoted = false;

  for(let i = 0; i < text.length; i++){

    const char = text[i];
    const next = text[i + 1];

    if(char === '"'){

      if(quoted && next === '"'){
        field += '"';
        i++;
      }else{
        quoted = !quoted;
      }

      continue;
    }

    if(char === "," && !quoted){

      row.push(field);
      field = "";

      continue;
    }

    if(
      (char === "\n" || char === "\r") &&
      !quoted
    ){

      if(
        char === "\r" &&
        next === "\n"
      ){
        i++;
      }

      row.push(field);

      if(
        row.some(value =>
          onlineClean(value) !== ""
        )
      ){
        rows.push(row);
      }

      row = [];
      field = "";

      continue;
    }

    field += char;
  }

  if(field !== "" || row.length){

    row.push(field);

    if(
      row.some(value =>
        onlineClean(value) !== ""
      )
    ){
      rows.push(row);
    }
  }

  if(rows.length < 2){
    return [];
  }

  const headings =
    rows[0].map(value =>
      onlineClean(value)
        .replace(/^\uFEFF/, "")
    );

  return rows
    .slice(1)
    .map(values => {

      const item = {};

      headings.forEach(
        (heading, index) => {

          item[heading] =
            values[index] ?? "";

        }
      );

      return item;
    });
}


function onlineDateActive(
  startValue,
  endValue
){

  const parseDate = value => {

    const text =
      onlineClean(value);

    if(!text){
      return null;
    }

    const iso =
      text.match(
        /^(\d{4})-(\d{2})-(\d{2})$/
      );

    const date =
      iso
        ? new Date(
            Number(iso[1]),
            Number(iso[2]) - 1,
            Number(iso[3])
          )
        : new Date(text);

    return Number.isNaN(
      date.getTime()
    )
      ? null
      : date;
  };


  const today =
    new Date();

  today.setHours(
    0,
    0,
    0,
    0
  );


  const start =
    parseDate(startValue);

  const end =
    parseDate(endValue);


  if(start){

    start.setHours(
      0,
      0,
      0,
      0
    );

    if(today < start){
      return false;
    }
  }


  if(end){

    end.setHours(
      23,
      59,
      59,
      999
    );

    if(today > end){
      return false;
    }
  }


  return true;
}


function trustedOnlinePrice(item){

  const msrp =
    onlineMoney(item.MSRP);

  const salePrice =
    onlineDateActive(
      item.SaleStartDate,
      item.SaleEndDate
    )
      ? onlineMoney(
          item.SalePrice
        )
      : 0;


  const rebate =
    onlineDateActive(
      item.RebateStartDate,
      item.RebateEndDate
    )
      ? (
          onlineClean(
            item.RebateToCustomer
          ) !== ""
            ? onlineMoney(
                item.RebateToCustomer
              )
            : onlineMoney(
                item.CustomerRebateAmount
              )
        )
      : 0;


  const basePrice =
    salePrice ||
    msrp ||
    0;


  return Number(
    Math.max(
      basePrice - rebate,
      0
    ).toFixed(2)
  );
}


async function getTrustedOnlineProduct(
  sku
){

  const response =
    await fetch(
      ONLINE_PRODUCTS_CSV,
      {
        cache:"no-store"
      }
    );


  if(!response.ok){

    throw new Error(
      "Unable to load trusted product data."
    );
  }


  const csv =
    await response.text();


  const products =
    parseOnlineCSV(csv);


  const requestedSKU =
    onlineClean(sku)
      .toUpperCase();


  return products.find(product => {

    const productSKU =
      onlineClean(
        product.SKU ||
        product.StihlID ||
        product.STIHLID ||
        product["STIHL ID"]
      ).toUpperCase();

    return (
      productSKU ===
      requestedSKU
    );

  }) || null;
}

async function handleOnlineOrder(
  request,
  env,
  corsHeaders
){

  try{

    await ensureOnlineOrdersTable(env);

    const data =
      await request.json();

    const customer =
      data.customer || {};

    const item =
      data.item || {};

    const shipping =
      data.shipping || {};

    const firstName =
      String(
        customer.firstName || ""
      ).trim();

    const lastName =
      String(
        customer.lastName || ""
      ).trim();

    const address1 =
      String(
        customer.address1 || ""
      ).trim();

    const address2 =
      String(
        customer.address2 || ""
      ).trim();

    const city =
      String(
        customer.city || ""
      ).trim();

    const state =
      String(
        customer.state || ""
      )
      .trim()
      .toUpperCase();

    const zip =
      String(
        customer.zip || ""
      ).trim();

    const phone =
      String(
        customer.phone || ""
      ).trim();

    const email =
      String(
        customer.email || ""
      ).trim();

    const sku =
      String(
        item.sku || ""
      ).trim();


    if(!sku){

      return Response.json(
        {
          error:
            "A valid product SKU is required."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }


    /*
      Buy Online currently processes
      one product per online order.
      Do not trust quantity from browser.
    */
    const quantity = 1;


    /*
      Server-side product lookup.
      The browser is NOT the authority
      for price, inventory, or eligibility.
    */
    const trustedProduct =
      await getTrustedOnlineProduct(
        sku
      );


    if(!trustedProduct){

      return Response.json(
        {
          error:
            "This product is no longer available for online ordering."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }


    /*
      If Active contains a value,
      it must be a true value.
    */
    if(
      onlineClean(
        trustedProduct.Active
      ) !== "" &&
      !onlineTrue(
        trustedProduct.Active
      )
    ){

      return Response.json(
        {
          error:
            "This product is not currently active."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }


    if(
      !onlineTrue(
        trustedProduct.BuyOnlineEligible
      )
    ){

      return Response.json(
        {
          error:
            "This product is not currently available for online purchase."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }


    const inventoryAvailable =
      value => {

        const text =
          onlineClean(value);

        if(!text){
          return false;
        }

        if(onlineTrue(text)){
          return true;
        }

        const qty =
          Number(
            text.replace(/,/g, "")
          );

        return (
          Number.isFinite(qty) &&
          qty > 0
        );
      };


    const inStock =
      inventoryAvailable(
        trustedProduct.QtyNewMilford
      ) ||
      inventoryAvailable(
        trustedProduct.QtyDanbury
      );


    if(!inStock){

      return Response.json(
        {
          error:
            "This product is not currently in stock. Please request availability."
        },
        {
          status:409,
          headers:corsHeaders
        }
      );
    }


    /*
      Product name and selling price
      come from trusted products.csv.
    */
    const productName =
      onlineClean(
        trustedProduct.ProductName ||
        trustedProduct.Name ||
        trustedProduct.Description ||
        sku
      );


    const itemPrice =
      trustedOnlinePrice(
        trustedProduct
      );


    if(itemPrice <= 0){

      return Response.json(
        {
          error:
            "A valid online selling price could not be determined."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }


    const fulfillment =
      String(
        data.fulfillment || ""
      ).trim();

    const validFulfillment =
      [
        "SHIP",
        "PICKUP_NEW_MILFORD",
        "PICKUP_DANBURY"
      ];

    if(
      !firstName ||
      !lastName ||
      !address1 ||
      !city ||
      !/^[A-Z]{2}$/.test(state) ||
      !/^\d{5}$/.test(zip) ||
      !phone ||
      !email
    ){
      return Response.json(
        {
          error:
            "Complete customer information is required."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }

    if(
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        email
      )
    ){
      return Response.json(
        {
          error:
            "A valid email address is required."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }

    if(
      !sku ||
      !productName ||
      itemPrice <= 0
    ){
      return Response.json(
        {
          error:
            "Valid order item information is required."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }

    if(
      !validFulfillment.includes(
        fulfillment
      )
    ){
      return Response.json(
        {
          error:
            "A valid fulfillment method is required."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }

    if(data.termsAccepted !== true){
      return Response.json(
        {
          error:
            "Final-sale and fitment terms must be accepted."
        },
        {
          status:400,
          headers:corsHeaders
        }
      );
    }


    let pickupLocation = "";
    let carrier = "";
    let service = "";
    let shippingAmount = 0;
    let shippingZIP = "";
    let estimatedTransitDays = null;


    if(
      fulfillment ===
      "PICKUP_NEW_MILFORD"
    ){
      pickupLocation =
        "New Milford";
    }


    if(
      fulfillment ===
      "PICKUP_DANBURY"
    ){
      pickupLocation =
        "Danbury";
    }


    if(fulfillment === "SHIP"){

      /*
        ======================================================
        SERVER-VERIFIED UPS GROUND SHIPPING
        Never trust shipping price or dimensions supplied
        by the customer's browser.
        ======================================================
      */

      const shippingRestriction =
        onlineClean(
          trustedProduct.ShippingRestriction
        ).toUpperCase();


      if(
        !onlineTrue(
          trustedProduct.ShippingEligible
        ) ||
        shippingRestriction ===
          "NO_SHIPPING"
      ){

        return Response.json(
          {
            error:
              "Shipping is not available for this product."
          },
          {
            status:400,
            headers:corsHeaders
          }
        );
      }


      /*
        Dimensions come only from the
        trusted published products.csv.
      */

      const trustedWeight =
        onlineMoney(
          trustedProduct.ShipWeight
        );

      const trustedLength =
        onlineMoney(
          trustedProduct.ShipLength
        );

      const trustedWidth =
        onlineMoney(
          trustedProduct.ShipWidth
        );

      const trustedHeight =
        onlineMoney(
          trustedProduct.ShipHeight
        );


      if(
        trustedWeight <= 0 ||
        trustedLength <= 0 ||
        trustedWidth <= 0 ||
        trustedHeight <= 0
      ){

        return Response.json(
          {
            error:
              "Shipping is not available because package dimensions are incomplete."
          },
          {
            status:400,
            headers:corsHeaders
          }
        );
      }


      /*
        Reuse our existing UPS Rating
        function internally.

        Destination ZIP comes from the
        validated customer address.

        Weight and dimensions come from
        trusted products.csv.
      */

      const trustedRateRequest =
        new Request(
          "https://internal.westendpower/shipping-rate",
          {
            method:"POST",

            headers:{
              "Content-Type":
                "application/json"
            },

            body:
              JSON.stringify({
                destinationZIP:
                  zip,

                weight:
                  trustedWeight,

                length:
                  trustedLength,

                width:
                  trustedWidth,

                height:
                  trustedHeight
              })
          }
        );


      const trustedRateResponse =
        await handleShippingRate(
          trustedRateRequest,
          env,
          corsHeaders
        );


      const trustedRate =
        await trustedRateResponse.json();


      if(
        !trustedRateResponse.ok ||
        trustedRate.ok !== true ||
        Number(
          trustedRate.amount
        ) <= 0
      ){

        console.log(
          "Server UPS verification failed:",
          trustedRate
        );

        return Response.json(
          {
            error:
              "UPS Ground shipping could not be verified. Please try again."
          },
          {
            status:502,
            headers:corsHeaders
          }
        );
      }


      /*
        These values are now server generated.

        Browser-supplied shipping.amount,
        carrier, service, dimensions and
        transit time are NOT trusted.
      */

      carrier =
        "UPS";

      service =
        "UPS Ground";

      shippingAmount =
        Number(
          Number(
            trustedRate.amount
          ).toFixed(2)
        );

      shippingZIP =
        zip;

      estimatedTransitDays =
        Number(
          trustedRate
            .businessDaysInTransit
        ) || null;

    }


    const subtotal =
      Number(
        (
          (itemPrice * quantity) +
          shippingAmount
        ).toFixed(2)
      );

    /*
      Tax and final payment total will be
      calculated during the Stripe stage.
    */

    const tax = 0;

    const total =
      subtotal;

    const now =
      new Date().toISOString();

    const termsAcceptedAt =
      now;

    // Public order numbers stay human-friendly; this token authorizes checkout.
    const checkoutToken =
      crypto.randomUUID();


    const insertResult =
      await env.QUOTES_DB.prepare(`
        INSERT INTO online_orders (

          created_at,
          updated_at,

          status,
          payment_status,

          first_name,
          last_name,
          address_line1,
          address_line2,
          city,
          state,
          zip,
          phone,
          email,
          checkout_token,

          sku,
          product_name,
          quantity,
          item_price,

          fulfillment,
          pickup_location,

          carrier,
          service,
          shipping_amount,
          shipping_zip,

          subtotal,
          tax,
          total,

          estimated_transit_days,

          terms_version,
          terms_text,
          terms_accepted,
          terms_accepted_at,

          stripe_session_id,
          stripe_payment_intent,

          tracking_number,
          internal_notes,

          payload_json

        ) VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?
        )
      `).bind(

        now,
        now,

        "PENDING_PAYMENT",
        "UNPAID",

        firstName,
        lastName,
        address1,
        address2,
        city,
        state,
        zip,
        phone,
        email,
        checkoutToken,

        sku,
        productName,
        quantity,
        itemPrice,

        fulfillment,
        pickupLocation,

        carrier,
        service,
        shippingAmount,
        shippingZIP,

        subtotal,
        tax,
        total,

        estimatedTransitDays,

        ONLINE_TERMS_VERSION,
        ONLINE_TERMS_TEXT,
        1,
        termsAcceptedAt,

        "",
        "",

        "",
        "",

        JSON.stringify(data)

      ).run();


    const orderID =
      Number(
        insertResult
          ?.meta
          ?.last_row_id
      );


    if(!orderID){
      throw new Error(
        "Online order record was not created."
      );
    }


    const orderNumber =
      `WEB-${onlineOrderDateCode()}-${String(
        orderID
      ).padStart(5, "0")}`;


    await env.QUOTES_DB.prepare(`
      UPDATE online_orders
      SET
        order_number = ?,
        updated_at = ?
      WHERE id = ?
    `).bind(
      orderNumber,
      now,
      orderID
    ).run();


    return Response.json(
      {
        ok:true,
        orderID,
        orderNumber,
        checkoutToken,
        status:"PENDING_PAYMENT",
        paymentStatus:"UNPAID",
        subtotal,
        tax,
        total,
        termsVersion:
          ONLINE_TERMS_VERSION,
        termsAcceptedAt
      },
      {
        headers:corsHeaders
      }
    );


  }catch(error){

    console.log(
      "Online order error:",
      error
    );

    return Response.json(
      {
        error:
          error?.message ||
          "Online order could not be created."
      },
      {
        status:500,
        headers:corsHeaders
      }
    );

  }

}

async function handleQuoteManager(env, request) {
  const url = new URL(request.url);

  const q =
    (url.searchParams.get("q") || "").trim();

  const statusFilter =
    (url.searchParams.get("status") || "").trim();

  const id =
    url.searchParams.get("id");

  if(id){
    return handleQuoteDetail(env, id);
  }

  let result;

  if(q && statusFilter){
    const like = `%${q}%`;

    result = await env.QUOTES_DB.prepare(`
      SELECT
        id,
        quote_number,
        created_at,
        salesperson,
        customer,
        phone,
        selected_tool,
        total,
        status
      FROM quotes
      WHERE status = ?
        AND (
          quote_number LIKE ?
          OR customer LIKE ?
          OR phone LIKE ?
          OR salesperson LIKE ?
          OR selected_tool LIKE ?
        )
      ORDER BY id DESC
      LIMIT 50
    `).bind(
      statusFilter,
      like,
      like,
      like,
      like,
      like
    ).all();

  }else if(statusFilter){

    result = await env.QUOTES_DB.prepare(`
      SELECT
        id,
        quote_number,
        created_at,
        salesperson,
        customer,
        phone,
        selected_tool,
        total,
        status
      FROM quotes
      WHERE status = ?
      ORDER BY id DESC
      LIMIT 50
    `).bind(statusFilter).all();

  }else if(q){
    const like = `%${q}%`;

    result = await env.QUOTES_DB.prepare(`
      SELECT
        id,
        quote_number,
        created_at,
        salesperson,
        customer,
        phone,
        selected_tool,
        total,
        status
      FROM quotes
      WHERE
        quote_number LIKE ?
        OR customer LIKE ?
        OR phone LIKE ?
        OR salesperson LIKE ?
        OR selected_tool LIKE ?
      ORDER BY id DESC
      LIMIT 50
    `).bind(
      like,
      like,
      like,
      like,
      like
    ).all();

  }else{

    result = await env.QUOTES_DB.prepare(`
      SELECT
        id,
        quote_number,
        created_at,
        salesperson,
        customer,
        phone,
        selected_tool,
        total,
        status
      FROM quotes
      ORDER BY id DESC
      LIMIT 50
    `).all();
  }

  const rows = (result.results || []).map(q => `
    <tr>
      <td>${escapeHtml(q.id)}</td>
      <td>
  <a href="/quotes?id=${encodeURIComponent(q.id)}">
    ${escapeHtml(q.quote_number)}
  </a>
</td>
      <td>${escapeHtml(formatDate(q.created_at))}</td>
      <td>${escapeHtml(q.salesperson)}</td>
      <td>${escapeHtml(q.customer)}</td>
      <td>${escapeHtml(q.phone)}</td>
      <td>${escapeHtml(q.selected_tool)}</td>
      <td>${escapeHtml(quoteCurrency(q.total))}</td>
      <td>${escapeHtml(q.status)}</td>
    </tr>
  `).join("");

  return new Response(`
    <!doctype html>
    <html>
    <head>
      <title>West End Power Quote Manager</title>
      <p>
  <a href="/dashboard">Dashboard</a>
</p>
      <style>
        body{font-family:Arial;margin:20px;background:#f7f7f7;color:#111;}
        h1{margin-bottom:10px;}
        form{margin:14px 0;display:flex;gap:8px;}
        input{padding:10px;font-size:15px;width:360px;max-width:100%;}
        button{padding:10px 14px;font-weight:bold;background:#111;color:#fff;border:0;border-radius:6px;}
        table{width:100%;border-collapse:collapse;background:#fff;}
        th,td{border:1px solid #ddd;padding:8px;font-size:13px;text-align:left;}
        th{background:#111;color:#fff;}
        tr:nth-child(even){background:#fafafa;}
      </style>
    </head>
    <body>
      <h1>West End Power Quote Manager</h1>

      <form method="get" action="/quotes">
        ${statusFilter ? `
          <input type="hidden" name="status" value="${escapeHtml(statusFilter)}">
        ` : ""}

        <input
          type="search"
          name="q"
          value="${escapeHtml(q)}"
          placeholder="Search quote #, customer, phone, salesperson, or product"
          aria-label="Search quotes"
        >

        <button type="submit">Search</button>

        <a
          href="${statusFilter
            ? `/quotes?status=${encodeURIComponent(statusFilter)}`
            : "/quotes"}"
          style="padding:10px 14px;"
        >
          Clear Search
        </a>

        ${statusFilter ? `
          <a href="/quotes" style="padding:10px 14px;">
            View All Quotes
          </a>
        ` : ""}

      </form>

      <p>
        ${
          statusFilter
            ? `<strong>${
                statusFilter === "Ordered"
                  ? "Sales Orders"
                  : statusFilter === "Sold"
                    ? "Sold Orders"
                    : `${escapeHtml(statusFilter)} Quotes`
              }</strong> &mdash; `
            : ""
        }

        ${
          q
            ? `Search results for: <strong>${escapeHtml(q)}</strong>`
            : "Most recent 50 records"
        }
      </p>

      <table>
        <tr>
          <th>ID</th>
          <th>Quote #</th>
          <th>Date</th>
          <th>Salesperson</th>
          <th>Customer</th>
          <th>Phone</th>
          <th>Selected Tool</th>
          <th>Total</th>
          <th>Status</th>
        </tr>
        ${rows || `<tr><td colspan="9">No quotes found.</td></tr>`}
      </table>
    </body>
    </html>
  `, {
    headers: { "Content-Type": "text/html" }
  });
}

async function handleQuoteDetail(env, id) {
  const result = await env.QUOTES_DB.prepare(`
    SELECT *
    FROM quotes
    WHERE id = ?
    LIMIT 1
  `).bind(id).first();

  if(!result){
    return new Response("Quote not found", { status: 404 });
  }

  let payload = {};
  try {
    payload = JSON.parse(result.payload_json || "{}");
  } catch(e) {
    payload = {};
  }

  const items = Array.isArray(payload.items) ? payload.items : [];
  const trade = payload.trade || null;
  const notesResult = await env.QUOTES_DB.prepare(`
  SELECT
    id,
    created_at,
    salesperson,
    note
  FROM quote_notes
  WHERE quote_id = ?
  ORDER BY id DESC
`).bind(id).all();

const internalNotes = notesResult.results || [];

const savedPayments =
  Array.isArray(payload.payments)
    ? payload.payments
    : [];

const activePayments =
  savedPayments.filter(payment =>
    String(
      payment.status || "received"
    ).toLowerCase() !== "voided"
  );

const totalReceived =
  activePayments.reduce(
    (total, payment) =>
      total +
      (
        Number(payment.amount) ||
        0
      ),
    0
  );

const orderTotal =
  Number(
    String(result.total || "")
      .replace(/[$,]/g, "")
  ) || 0;

const balanceDue =
  Math.max(
    orderTotal -
    totalReceived,
    0
  );

const paymentRows =
  savedPayments.map(payment => `
    <tr>
      <td>
        ${escapeHtml(
          payment.date || ""
        )}
      </td>

      <td>
        ${escapeHtml(
          payment.method ||
          (
            String(
              payment.methodKey || ""
            ).includes("credit")
              ? "Credit Card"
              : String(
                  payment.methodKey || ""
                ).includes("debit")
                ? "Debit Card"
                : String(
                    payment.methodKey || ""
                  ).includes("cash")
                  ? "Cash / Bank Check"
                  : String(
                      payment.methodKey || ""
                    ).includes("finance")
                    ? "Financing"
                    : "Payment"
          )
        )}

        ${payment.cardType
          ? ` &mdash; ${escapeHtml(payment.cardType)}`
          : ""}
      </td>

      <td>
        ${escapeHtml(
          payment.reference || "-"
        )}
      </td>

      <td>
        ${escapeHtml(
          payment.receivedBy || ""
        )}
      </td>

      <td style="text-align:right;">
        ${escapeHtml(
          Number(
            payment.amount || 0
          ).toLocaleString(
            "en-US",
            {
              style:"currency",
              currency:"USD"
            }
          )
        )}
      </td>

      <td>
        ${escapeHtml(
          payment.status || "received"
        )}
      </td>

      <td>
        ${
          String(payment.status || "received").toLowerCase() !== "voided" &&
          String(payment.id || "").trim()
            ? `<button
                type="button"
                class="screen-only"
                onclick='voidDashboardPayment(${JSON.stringify(String(payment.id))})'
                style="background:#b00020;color:#fff;border:0;border-radius:6px;padding:6px 10px;font-weight:800;cursor:pointer;"
              >Void</button>`
            : ""
        }
      </td>
    </tr>
  `).join("");

const internalNotesHtml = internalNotes.map(n => `
  <div style="
    border:1px solid #ddd;
    border-radius:8px;
    padding:10px;
    margin-bottom:8px;
    background:#fafafa;
  ">
    <div style="font-size:12px;color:#666;margin-bottom:6px;">
      ${escapeHtml(formatDate(n.created_at))} - ${escapeHtml(n.salesperson)}
    </div>
    <div>${escapeHtml(n.note)}</div>
  </div>
`).join("");

  const itemRows = items.map(item => {

    const quantity =
      Number(item.qty) || 1;

    const lineTotal =
      Number(
        String(
          item.repricedLineTotal ??
          item.lineTotal ??
          ""
        )
          .replace(/[$,]/g, "")
      ) || 0;

    const unitPrice =
      Number(
        String(item.price || "")
          .replace(/[$,]/g, "")
      ) ||
      (
        lineTotal > 0
          ? lineTotal / quantity
          : 0
      );

    return `
      <tr>
        <td>${escapeHtml(quantity)}</td>

        <td>
          ${escapeHtml(item.name || "")}
        </td>

        <td>
          ${escapeHtml(
            unitPrice.toLocaleString(
              "en-US",
              {
                style:"currency",
                currency:"USD"
              }
            )
          )}
        </td>

        <td>
          ${escapeHtml(
            lineTotal.toLocaleString(
              "en-US",
              {
                style:"currency",
                currency:"USD"
              }
            )
          )}
        </td>
      </tr>
    `;
  }).join("");

  const tradePhotos =
    trade && Array.isArray(trade.photos)
      ? trade.photos.slice(0, 8).map(photo => `
          <img src="${escapeHtml(photo.dataUrl || "")}"
               style="width:140px;height:105px;object-fit:cover;border:1px solid #ddd;border-radius:8px;margin:4px;">
        `).join("")
      : "";

  return new Response(`
    <!doctype html>
    <html>
    <head>
      <title>Quote ${escapeHtml(result.quote_number)}</title>
      <style>
        body{font-family:Arial;margin:0;background:#f4f4f4;color:#111;}
        .wrap{max-width:1150px;margin:0 auto;padding:20px;}
        .top{background:#111;color:#fff;padding:18px 22px;border-bottom:6px solid #f37021;}
        .top h1{margin:0;font-size:26px;}
        .top p{margin:6px 0 0;color:#ddd;}
        .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
        .card{background:#fff;border:1px solid #ddd;border-radius:12px;padding:16px;margin-bottom:16px;box-shadow:0 2px 8px rgba(0,0,0,.04);}
        .card h2{margin:0 0 10px;font-size:20px;border-bottom:2px solid #f37021;padding-bottom:6px;}
        .line{display:flex;justify-content:space-between;border-bottom:1px solid #eee;padding:6px 0;gap:14px;}
        .line span{color:#555;}
        .line strong{text-align:right;}
        table{width:100%;border-collapse:collapse;background:#fff;}
        th,td{border:1px solid #ddd;padding:8px;font-size:13px;text-align:left;}
        th{background:#111;color:#fff;}
        a{color:#111;font-weight:bold;}
        .btn{display:inline-block;padding:10px 14px;background:#111;color:#fff;text-decoration:none;border-radius:8px;margin-right:8px;font-weight:bold;}
        .btn.orange{background:#f37021;color:#111;}
        .status{display:inline-block;background:#effaf2;border:1px solid #1f7a3a;color:#1f7a3a;border-radius:999px;padding:6px 10px;font-weight:bold;}
        .print-only{display:none;}

        @media(max-width:800px){
          .grid{grid-template-columns:1fr;}
        }

        @media print{
          @page{
            size:letter portrait;
            margin:0.45in;
          }

          body{
            background:#fff;
          }

          .wrap{
            max-width:none;
            padding:0;
          }

          .top{
            background:#fff;
            color:#111;
            border-bottom:5px solid #f37021;
            padding:0 0 12px;
          }

          .top p{
            color:#333;
          }

          .card{
            box-shadow:none;
            break-inside:avoid;
          }

          .screen-only{
            display:none !important;
          }

          .print-only{
            display:block !important;
          }

          table{
            break-inside:avoid;
          }
        }
      </style>
    </head>
    <body>
      <div class="top">
        <h1>
          ${
            result.status === "Sold" ||
            balanceDue <= 0.009
              ? "Final Sales Receipt"
              : result.status === "Ordered"
                ? "Sales Order"
                : "Quote"
          }
          ${escapeHtml(result.quote_number)}
        </h1>

        <p>
          ${escapeHtml(formatDate(result.created_at))}
          &bull;
          ${escapeHtml(result.configurator || "")}
        </p>
      </div>

      <div class="wrap">
        <p class="screen-only">
  <a href="/quotes">&larr; Back to Quote Manager</a>
  &nbsp; | &nbsp;
  <a href="/dashboard">Dashboard</a>
</p>

         <div class="print-only" style="margin-bottom:14px;">
          <h2 style="margin:0;">
            ${
              balanceDue <= 0.009
                ? "Final Sales Receipt — Paid in Full"
                : totalReceived > 0
                  ? "Updated Sales Order / Payment Receipt"
                  : "Sales Order Confirmation"
            }
          </h2>

          <div style="margin-top:5px;">
            <strong>Status:</strong>
            ${escapeHtml(result.status)}
            &nbsp; | &nbsp;
            <strong>Prepared By:</strong>
            ${escapeHtml(result.salesperson)}
          </div>
        </div>

        <div class="card screen-only">
          <div class="line">
  <span>Status</span>
  <strong>
    <select id="quote-status" style="padding:7px;border-radius:6px;">
      ${["Open","Waiting on Customer","Ordered","Sold","Lost","Cancelled"].map(s => `
        <option value="${s}" ${result.status === s ? "selected" : ""}>${s}</option>
      `).join("")}
    </select>

    <button onclick="saveStatus()" style="padding:7px 10px;margin-left:6px;">
      Save
    </button>
  </strong>
</div>

<div id="status-message" style="margin:8px 0;color:#1f7a3a;font-weight:bold;"></div>
          <div class="line">
            <span>Salesperson</span>
            <strong>${escapeHtml(result.salesperson)}</strong>
          </div>
          <div class="line">
            <span>Total</span>
            <strong>${escapeHtml(quoteCurrency(result.total))}</strong>
          </div>
        </div>

        <div class="line screen-only">
  <span>Follow-Up Date</span>
  <strong>
    <input id="follow-up-date"
           type="date"
           value="${escapeHtml(result.follow_up_date || "")}"
           style="padding:7px;border-radius:6px;">
    <button onclick="saveFollowUp()" style="padding:7px 10px;margin-left:6px;">
      Save
    </button>
  </strong>
</div>

<div class="screen-only" id="followup-message" style="margin:8px 0;color:#1f7a3a;font-weight:bold;"></div>

        <div class="grid">
          <div class="card">
            <h2>Customer</h2>

            <div class="line">
              <span>Name</span>
              <strong id="quote-customer-name">${escapeHtml(result.customer)}</strong>
            </div>

            <div class="line">
              <span>Business</span>
              <strong id="quote-customer-business">${escapeHtml(result.business)}</strong>
            </div>

            <div class="line">
              <span>Phone</span>
              <strong id="quote-customer-phone">${escapeHtml(result.phone)}</strong>
            </div>

            <div class="line">
              <span>Alternate Phone</span>
              <strong id="quote-customer-alt-phone">${escapeHtml(result.alt_phone)}</strong>
            </div>

            <div class="line">
              <span>Email</span>
              <strong id="quote-customer-email">${escapeHtml(result.email)}</strong>
            </div>

            <div class="line">
              <span>Address</span>
              <strong id="quote-customer-address">${escapeHtml(result.address)}</strong>
            </div>

            <div class="screen-only" style="margin-top:12px;">
              <button
                type="button"
                onclick="editQuoteCustomer()"
                style="padding:8px 12px;font-weight:bold;"
              >
                Edit Customer / Address
              </button>

              <div
                id="quote-customer-message"
                style="margin-top:8px;color:#1f7a3a;font-weight:bold;"
              ></div>
            </div>
          </div>

          <div class="card">
            <h2>Quote Summary</h2>
            <div class="line"><span>Selected Tool</span><strong>${escapeHtml(result.selected_tool)}</strong></div>
            <div class="line"><span>Subtotal</span><strong>${escapeHtml(quoteCurrency(result.subtotal))}</strong></div>
            ${quoteMoney(trade?.allowance) > 0 ? `
              <div class="line">
                <span>Trade-In Allowance</span>
                <strong>-${escapeHtml(
                  quoteMoney(trade.allowance)
                    .toLocaleString("en-US", {style:"currency", currency:"USD"})
                )}</strong>
              </div>
            ` : ""}
            <div class="line"><span>Tax</span><strong>${escapeHtml(quoteCurrency(result.tax))}</strong></div>
            <div class="line"><span>Total</span><strong>${escapeHtml(quoteCurrency(result.total))}</strong></div>
            ${quoteMoney(payload.paymentMethodPriceAdjustment) !== 0 ? `
              <div class="line" style="color:#b00020;">
                <span>Payment Method Price Adjustment</span>
                <strong>${escapeHtml(
                  quoteMoney(payload.paymentMethodPriceAdjustment)
                    .toLocaleString("en-US", {style:"currency", currency:"USD"})
                )}</strong>
              </div>
            ` : ""}
            <div class="line"><span>Delivery / Pickup</span><strong>${escapeHtml(result.delivery)}</strong></div>
             ${result.payment ? `
              <div class="line">
                <span>Customer Selected Payment Option</span>
                <strong>${escapeHtml(result.payment)}</strong>
              </div>
            ` : ""}
                    </div>
        </div>

        <div class="card">
          <h2>Customer Note</h2>

          <div
            id="quote-customer-note"
            style="
              white-space:pre-wrap;
              line-height:1.5;
              min-height:24px;
            "
          >${escapeHtml(payload.customerNote || "")}</div>

          ${!payload.customerNote ? `
            <div
              class="screen-only"
              id="quote-customer-note-empty"
              style="color:#666;"
            >
              No customer note has been entered.
            </div>
          ` : ""}

          <div
            class="screen-only"
            style="margin-top:12px;"
          >
            <button
              type="button"
              onclick="editQuoteCustomerNote()"
              style="
                padding:8px 12px;
                font-weight:bold;
              "
            >
              Edit Customer Note
            </button>

            <div
              id="quote-customer-note-message"
              style="
                margin-top:8px;
                color:#1f7a3a;
                font-weight:bold;
              "
            ></div>
          </div>
        </div>

        <div class="card">
          <h2>Equipment & Items</h2>
          <table>
            <tr><th>Qty</th><th>Item</th><th>Unit Price</th><th>Line Total</th></tr>
            ${itemRows || `<tr><td colspan="4">No items found.</td></tr>`}
          </table>
        </div>

        ${trade ? `
          <div class="card">
            <h2>Trade-In</h2>
            <div class="line"><span>Trade</span><strong>${escapeHtml([trade.year, trade.make, trade.model].filter(Boolean).join(" "))}</strong></div>
            ${trade.hours ? `<div class="line"><span>Hours</span><strong>${escapeHtml(trade.hours)}</strong></div>` : ""}
            ${trade.condition ? `<div class="line"><span>Condition</span><strong>${escapeHtml(trade.condition)}</strong></div>` : ""}
            ${trade.allowance ? `<div class="line"><span>Allowance</span><strong>$${escapeHtml(Number(trade.allowance).toLocaleString())}</strong></div>` : ""}
            ${trade.notes ? `<p><strong>Notes:</strong><br>${escapeHtml(trade.notes)}</p>` : ""}
            ${tradePhotos ? `<div style="margin-top:10px;">${tradePhotos}</div>` : ""}
          </div>
        ` : ""}

        <div class="card">
          <h2>Payments &amp; Balance</h2>

          <div class="grid" style="margin-bottom:14px;">
            <div class="line">
              <span>Total Received</span>
              <strong>
                ${escapeHtml(
                  totalReceived.toLocaleString(
                    "en-US",
                    {
                      style:"currency",
                      currency:"USD"
                    }
                  )
                )}
              </strong>
            </div>

            <div class="line">
              <span>Balance Due</span>
              <strong style="
                font-size:18px;
                color:${balanceDue > 0 ? "#b00020" : "#1f7a3a"};
              ">
                ${escapeHtml(
                  balanceDue.toLocaleString(
                    "en-US",
                    {
                      style:"currency",
                      currency:"USD"
                    }
                  )
                )}
              </strong>
            </div>
          </div>

          <h3>Payment History</h3>

          <table>
            <tr>
              <th>Date</th>
              <th>Payment Method</th>
              <th>Reference</th>
              <th>Received By</th>
              <th style="text-align:right;">Amount</th>
              <th>Status</th>
              <th class="screen-only">Action</th>
            </tr>

            ${paymentRows || `
              <tr>
                <td colspan="7">
                  No payments recorded.
                </td>
              </tr>
            `}
          </table>

          <div class="screen-only">

          <h3 style="margin-top:20px;">
            Record Additional Payment
          </h3>

          ${
            balanceDue > 0
              ? `
                <div class="grid">

                  <div>
                    <label for="payment-date">
                      Payment Date
                    </label>

                    <input
                      id="payment-date"
                      type="date"
                      value="${new Date().toISOString().slice(0,10)}"
                      style="width:100%;padding:9px;margin-top:4px;"
                    >
                  </div>

                  <div>
                    <label for="payment-amount">
                      Amount Received
                    </label>

                    <div style="display:flex;align-items:center;border:1px solid #777;border-radius:6px;background:#fff;margin-top:4px;overflow:hidden;">
                      <span aria-hidden="true" style="padding-left:10px;font-weight:900;">$</span>
                      <input
                        id="payment-amount"
                        type="number"
                        min="0.01"
                        max="${balanceDue.toFixed(2)}"
                        step="0.01"
                        placeholder="Enter payment amount"
                        style="width:100%;padding:9px;border:0;box-shadow:none;"
                      >
                    </div>
                  </div>

                  <div>
                    <label for="payment-method">
                      Payment Method
                    </label>

                    <select
                      id="payment-method"
                      style="width:100%;padding:9px;margin-top:4px;"
                    >
                      <option value="">
                        Select Payment Method
                      </option>
                      <option value="Cash / Bank Check">
                        Cash / Bank Check
                      </option>
                      <option value="Credit Card">
                        Credit Card
                      </option>
                      <option value="Debit Card">
                        Debit Card
                      </option>
                      <option value="Financing">
                        Financing
                      </option>
                      <option value="Other">
                        Other
                      </option>
                    </select>
                  </div>

                  <div>
                    <label for="payment-card-type">
                      Card Type, if applicable
                    </label>

                    <input
                      id="payment-card-type"
                      type="text"
                      placeholder="Visa, Mastercard, etc."
                      style="width:100%;padding:9px;margin-top:4px;"
                    >
                  </div>

                  <div>
                    <label for="payment-reference">
                      Reference
                    </label>

                    <input
                      id="payment-reference"
                      type="text"
                      placeholder="Receipt, check, or approval number"
                      style="width:100%;padding:9px;margin-top:4px;"
                    >
                  </div>

                  <div>
                    <label for="payment-received-by">
                      Received By
                    </label>

                    <input
                      id="payment-received-by"
                      type="text"
                      value="${escapeHtml(result.salesperson || "")}"
                      style="width:100%;padding:9px;margin-top:4px;"
                    >
                  </div>

                </div>

                <button
                  id="record-payment-button"
                  onclick="recordPayment()"
                  style="
                    margin-top:14px;
                    padding:11px 16px;
                    background:#1f7a3a;
                    color:#fff;
                    border:0;
                    border-radius:7px;
                    font-weight:bold;
                    cursor:pointer;
                  "
                >
                  Record Additional Payment
                </button>

                <div
                  id="payment-message"
                  style="
                    margin-top:8px;
                    font-weight:bold;
                  "
                ></div>
              `
              : `
                <div class="status">
                  Paid in Full
                </div>
              `
           }

          </div>
        </div>

        <div class="card screen-only">
  <h2>Internal Sales Notes</h2>

  <div id="notes-list">
    ${internalNotesHtml || `<p>No internal notes yet.</p>`}
  </div>

  <textarea id="new-note"
            style="width:100%;min-height:90px;padding:10px;margin-top:10px;"
            placeholder="Add internal note..."></textarea>

  <br><br>

  <button onclick="addNote()" style="padding:10px 14px;font-weight:bold;">
    Add Note
  </button>

  <div id="note-message" style="margin-top:8px;color:#1f7a3a;font-weight:bold;"></div>
</div>

        <div class="card screen-only">
          <h2>Actions</h2>

          <button
            type="button"
            class="btn orange"
            onclick="window.print()"
            style="
              border:0;
              cursor:pointer;
              font:inherit;
            "
          >
            ${
              balanceDue <= 0.009
                ? "Print Final Sales Receipt"
                : totalReceived > 0
                  ? "Print Updated Sales Order / Payment Receipt"
                  : "Print Sales Order Confirmation"
            }
          </button>

          <a class="btn" href="/quotes">
            Back to Quote Manager
          </a>
          <a class="btn orange" target="_blank" rel="noopener noreferrer" href="https://www.westendpower.com/payment-request-tool?quote=${encodeURIComponent(result.quote_number)}&customer=${encodeURIComponent(result.customer)}&email=${encodeURIComponent(result.email || "")}&amount=500&type=deposit&product=${encodeURIComponent(result.selected_tool)}">Request Deposit</a>
          <a class="btn orange"
target="_blank" rel="noopener noreferrer"
href="https://www.westendpower.com/payment-request-tool?quote=${encodeURIComponent(result.quote_number)}&customer=${encodeURIComponent(result.customer)}&email=${encodeURIComponent(result.email || "")}&amount=${encodeURIComponent(balanceDue.toFixed(2))}&type=full&product=${encodeURIComponent(result.selected_tool)}">
Request Remaining Balance
</a>
        </div>
      </div>

<script>

async function editQuoteCustomerNote(){

  const noteElement =
    document.getElementById(
      "quote-customer-note"
    );

  const currentNote =
    noteElement?.textContent.trim() || "";

  const customerNote = prompt(
    "Customer note shown on the printed quote:",
    currentNote
  );

  if(customerNote === null){
    return;
  }

  const message =
    document.getElementById(
      "quote-customer-note-message"
    );

  message.style.color = "#1f7a3a";
  message.textContent =
    "Saving customer note...";

  try{

    const response = await fetch(
      "/quote-customer-note",
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json"
        },

        body: JSON.stringify({
          id: ${Number(result.id)},
          customerNote
        })
      }
    );

    const data =
      await response.json()
      .catch(() => ({}));

    if(!response.ok){

      throw new Error(
        data.error ||
        "Customer note update failed."
      );
    }

    message.textContent =
      "Customer note updated.";

    window.location.reload();

  }catch(error){

    message.style.color = "#b00020";

    message.textContent =
      error.message ||
      "Customer note update failed.";
  }
}

async function editQuoteCustomer(){

  const valueOf = id =>
    document.getElementById(id)?.textContent.trim() || "";

  const customer = prompt(
    "Customer name:",
    valueOf("quote-customer-name")
  );

  if(customer === null) return;

  const business = prompt(
    "Business name:",
    valueOf("quote-customer-business")
  );

  if(business === null) return;

  const phone = prompt(
    "Phone:",
    valueOf("quote-customer-phone")
  );

  if(phone === null) return;

  const altPhone = prompt(
    "Alternate phone:",
    valueOf("quote-customer-alt-phone")
  );

  if(altPhone === null) return;

  const email = prompt(
    "Email:",
    valueOf("quote-customer-email")
  );

  if(email === null) return;

  const address = prompt(
    "Complete address:",
    valueOf("quote-customer-address")
  );

  if(address === null) return;

  const message =
    document.getElementById(
      "quote-customer-message"
    );

  message.textContent =
    "Saving customer information...";

  try{

    const response = await fetch(
      "/quote-customer",
      {
        method:"POST",

        headers:{
          "Content-Type":"application/json"
        },

        body:JSON.stringify({
          id:${Number(result.id)},
          customer,
          business,
          phone,
          altPhone,
          email,
          address
        })
      }
    );

    const data = await response.json()
      .catch(() => ({}));

    if(!response.ok){
      throw new Error(
        data.error ||
        "Customer update failed."
      );
    }

    message.textContent =
      "Customer information updated.";

    window.location.reload();

  }catch(error){

    message.style.color = "#b00020";
    message.textContent =
      error.message;
  }
}

async function voidDashboardPayment(paymentId){
  if(!paymentId) return;

  const approved = window.confirm(
    'Void this payment? The entry will remain in payment history.'
  );

  if(!approved) return;

  const response = await fetch(
    '/quote-payment-void',
    {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        quoteId:${Number(result.id)},
        paymentId
      })
    }
  );

  const result = await response.json()
    .catch(() => ({}));

  if(!response.ok){
    alert(result.error || 'Payment could not be voided.');
    return;
  }

  location.reload();
}

async function recordPayment(){

  const amount =
    Number(
      document.getElementById(
        'payment-amount'
      ).value
    );

  const paymentMethod =
    document.getElementById(
      'payment-method'
    ).value;

  const receivedBy =
    document.getElementById(
      'payment-received-by'
    ).value.trim();

  const message =
    document.getElementById(
      'payment-message'
    );

  const button =
    document.getElementById(
      'record-payment-button'
    );

  if(
    !Number.isFinite(amount) ||
    amount <= 0 ||
    !paymentMethod ||
    !receivedBy
  ){
    message.textContent =
      'Enter the amount received, payment method, and received by.';

    message.style.color =
      '#b00020';

    return;
  }

  const approved =
    window.confirm(
      'Record an actual payment of ' +
      amount.toLocaleString(
        'en-US',
        {
          style:'currency',
          currency:'USD'
        }
      ) +
      ' by ' +
      paymentMethod +
      '?'
    );

  if(!approved){
    return;
  }

  button.disabled = true;

  button.textContent =
    'Recording Payment...';

  message.textContent = '';

  const response =
    await fetch(
      '/quote-payment',
      {
        method:'POST',

        headers:{
          'Content-Type':
            'application/json'
        },

        body:JSON.stringify({
          quoteId:
            ${Number(result.id)},

          paymentDate:
            document.getElementById(
              'payment-date'
            ).value,

          amount,

          paymentMethod,

          paymentMethodKey:
            paymentMethod
              .toLowerCase()
              .replaceAll(' / ', '-')
              .replaceAll(' ', '-'),

          cardType:
            document.getElementById(
              'payment-card-type'
            ).value.trim(),

          reference:
            document.getElementById(
              'payment-reference'
            ).value.trim(),

          receivedBy
        })
      }
    );

  const result =
    await response.json()
      .catch(() => ({}));

  if(!response.ok){

    message.textContent =
      result.error ||
      'Payment could not be recorded.';

    message.style.color =
      '#b00020';

    button.disabled = false;

    button.textContent =
      'Record Additional Payment';

    return;
  }

  message.textContent =
    result.status === 'Sold'
      ? 'Payment recorded. Order is paid in full.'
      : 'Payment recorded successfully.';

  message.style.color =
    '#1f7a3a';

  setTimeout(
    () => location.reload(),
    700
  );
}

async function saveStatus(){
  const status = document.getElementById('quote-status').value;

  const res = await fetch('/quote-status', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      id: ${Number(result.id)},
      status
    })
  });

  document.getElementById('status-message').textContent =
    res.ok
  ? 'OK - Status Saved'
  : 'Error - Status failed';
}
  async function addNote(){
  const note = document.getElementById('new-note').value.trim();

  if(!note){
    document.getElementById('note-message').textContent = 'Enter a note first.';
    return;
  }

  const res = await fetch('/quote-note', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      quoteId: ${Number(result.id)},
      salesperson: ${JSON.stringify(result.salesperson || "")},
      note
    })
  });

  document.getElementById('note-message').textContent =
    res.ok ? 'Note added. Refreshing...' : 'Error - note failed';

  if(res.ok){
    setTimeout(() => location.reload(), 600);
  }
}

async function saveFollowUp(){
  const followUpDate = document.getElementById('follow-up-date').value;

  const res = await fetch('/quote-followup', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      id: ${Number(result.id)},
      followUpDate
    })
  });

  document.getElementById('followup-message').textContent =
    res.ok ? 'OK - Follow-up Saved' : 'Error - Follow-up failed';
}

</script>

    </body>
    </html>
`, {
     headers: {
      "Content-Type":
        "text/html; charset=UTF-8"
    }
  });
}

async function saveDealerQuoteState(
  request,
  env,
  corsHeaders
){
  const data =
    await request.json()
      .catch(() => ({}));

  const brandId =
    normalizeSupportedBrand(
      data?.brandId
    );

  const brandConfig =
    supportedBrandConfig(brandId);

  if(!brandConfig){
    return Response.json(
      {
        error:"Invalid quote brand."
      },
      {
        status:400,
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );
  }

  const authorized =
    await verifyDealerSessionToken(
      request,
      env,
      brandId
    );

  if(!authorized){
    return Response.json(
      {
        error:
          "Dealer session is invalid or expired."
      },
      {
        status:401,
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );
  }

  const quoteNumber =
    String(data.quoteNumber || "").trim();

  const allowedStatuses =
    new Set([
      "Open",
      "Ordered",
      "Sold"
    ]);

  const status =
    String(data.status || "Open").trim();

  if(
    !quoteNumber ||
    !allowedStatuses.has(status)
  ){
    return Response.json(
      {
        error:"Invalid quote state."
      },
      {
        status:400,
        headers:{
          ...corsHeaders,
          "Cache-Control":"no-store"
        }
      }
    );
  }

  const existing =
    await env.QUOTES_DB.prepare(`
      SELECT
        id,
        created_at,
        configurator,
        payment,
        tax,
        total,
        payload_json
      FROM quotes
      WHERE quote_number = ?
      LIMIT 1
    `).bind(
      quoteNumber
    ).first();

  let existingPayload = {};

  if(existing?.payload_json){
    try{
      existingPayload = JSON.parse(existing.payload_json || "{}");
    }catch(_error){
      existingPayload = {};
    }
  }

  const payload = {
    ...existingPayload,
    ...(data.payload || {}),
    orderNumber:
      String(data.orderNumber || ""),
    amountReceived:
      Number(data.amountReceived) || 0,
    balanceDue:
      Number(data.balanceDue) || 0,
    payments:
      Array.isArray(data.payments)
        ? data.payments
        : []
  };

  const salePaymentMethod = String(
    payload?.sale?.paymentType ||
    payload?.sale?.paymentMethod ||
    payload?.sale?.method ||
    ""
  ).trim();

  if(salePaymentMethod && payload.payments.length){
    const initialPayment = payload.payments[0];
    const currentMethod = String(initialPayment?.method || "").trim();

    if(
      initialPayment &&
      (!currentMethod || currentMethod.toLowerCase() === "other")
    ){
      initialPayment.method = salePaymentMethod;
      initialPayment.methodKey = salePaymentMethod
        .toLowerCase()
        .replaceAll(" / ", "-")
        .replaceAll(" ", "-");
    }
  }

  let savedTax = String(data.tax || "");
  let savedTotal = String(data.total || "");
  let savedStatus = status;
  const calculatedSubtotal =
    calculatedQuoteSubtotal(payload, data.subtotal);
  const savedSubtotal = calculatedSubtotal > 0
    ? `$${calculatedSubtotal.toFixed(2)}`
    : String(data.subtotal || "");

  if(existing && payload.payments.length){
    const locked = lockedQuoteAmounts(
      {
        ...existing,
        tax:String(data.tax || existing.tax || ""),
        total:String(data.total || existing.total || "")
      },
      payload
    );

    const received = payload.payments
      .filter(payment =>
        String(payment?.status || "received").toLowerCase() !== "voided"
      )
      .reduce(
        (sum, payment) => sum + (Number(payment?.amount) || 0),
        0
      );

    const balance = Math.max(locked.total - received, 0);

    payload.amountReceived = received;
    payload.balanceDue = balance;
    savedTax = `$${locked.tax.toFixed(2)}`;
    savedTotal = `$${locked.total.toFixed(2)}`;
    savedStatus =
      locked.total > 0 && balance <= 0.009
        ? "Sold"
        : payload.orderNumber
          ? "Ordered"
          : status;

    clearLegacyPaymentRepricing(payload);
  }

  if(existing){

    await env.QUOTES_DB.prepare(`
      UPDATE quotes
      SET
        salesperson = ?,
        customer = ?,
        phone = ?,
        email = ?,
        selected_tool = ?,
        subtotal = ?,
        tax = ?,
        total = ?,
        status = ?,
        payload_json = ?
      WHERE quote_number = ?
    `).bind(
      String(data.salesperson || ""),
      String(data.customer || ""),
      String(data.phone || ""),
      String(data.email || ""),
      String(data.selectedTool || ""),
      savedSubtotal,
      savedTax,
      savedTotal,
      savedStatus,
      JSON.stringify(payload),
      quoteNumber
    ).run();

  }else{

    await env.QUOTES_DB.prepare(`
      INSERT INTO quotes (
        quote_number,
        created_at,
        configurator,
        source,
        action,
        salesperson,
        customer,
        business,
        phone,
        alt_phone,
        email,
        address,
        delivery,
        payment,
        selected_tool,
        subtotal,
        tax,
        total,
        status,
        payload_json
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `).bind(
      quoteNumber,
      new Date().toISOString(),
      brandId,
      brandConfig.configuratorTitle,
      status === "Open"
        ? "Customer Quote"
        : status === "Ordered"
          ? "Sales Order"
          : "Completed Sale",
      String(data.salesperson || ""),
      String(data.customer || ""),
      String(data.business || ""),
      String(data.phone || ""),
      String(data.altPhone || ""),
      String(data.email || ""),
      String(data.address || ""),
      String(data.delivery || ""),
      String(data.payment || ""),
      String(data.selectedTool || ""),
      savedSubtotal,
      String(data.tax || ""),
      String(data.total || ""),
      status,
      JSON.stringify(payload)
    ).run();
  }

  return Response.json(
    {
      ok:true,
      quoteNumber,
      status
    },
    {
      headers:{
        ...corsHeaders,
        "Cache-Control":"no-store"
      }
    }
  );
}

function quoteMoney(value){
  return Number(
    String(value || "").replace(/[$,]/g, "")
  ) || 0;
}

function quoteCurrency(value){
  return quoteMoney(value).toLocaleString("en-US", {
    style:"currency",
    currency:"USD"
  });
}

function lockedQuoteAmounts(quote, payload){
  const legacyBase =
    payload && typeof payload.paymentPricingBase === "object"
      ? payload.paymentPricingBase
      : null;

  const total =
    quoteMoney(legacyBase?.originalTotal) ||
    quoteMoney(quote?.total);

  const tax =
    legacyBase && Number.isFinite(Number(legacyBase.originalTax))
      ? Number(legacyBase.originalTax)
      : quoteMoney(quote?.tax);

  return {total, tax};
}

function clearLegacyPaymentRepricing(payload){
  if(!payload || typeof payload !== "object") return;
  delete payload.paymentMethodPriceAdjustment;
  delete payload.repricedEquipmentTotal;
  delete payload.repricedTax;
  delete payload.repricedTotal;
  delete payload.actualPaymentMix;
  delete payload.paymentPricingBase;

  if(Array.isArray(payload.items)){
    payload.items.forEach(item => {
      if(item && typeof item === "object"){
        delete item.repricedLineTotal;
      }
    });
  }
}

function calculatedQuoteSubtotal(payload, fallback){
  const items = Array.isArray(payload?.items) ? payload.items : [];

  const equipment = items.reduce(
    (sum, item) => sum + quoteMoney(item?.lineTotal),
    0
  );

  if(equipment <= 0){
    return quoteMoney(fallback);
  }

  const totals = payload?.totals || {};
  const freight =
    totals.freight && typeof totals.freight === "object"
      ? quoteMoney(totals.freight.total)
      : quoteMoney(totals.freight);

  return equipment +
    freight +
    quoteMoney(totals.delivery) +
    quoteMoney(totals.setupInstallation) +
    quoteMoney(totals.extendedWarranty);
}

function quotePaymentClass(payment){
  const value = String(
    payment?.methodKey || payment?.method || ""
  ).toLowerCase();

  if(value.includes("credit") || value.includes("debit")){
    return "credit";
  }

  if(value.includes("finance")){
    return "finance";
  }

  return "cash";
}

async function repriceQuoteForPayments(
  quote,
  payload,
  payments,
  env
){
  const items = Array.isArray(payload.items)
    ? payload.items.filter(item => String(item?.sku || "").trim())
    : [];

  if(!items.length){
    return null;
  }

  const brandId = normalizeSupportedBrand(quote.configurator);

  if(!brandId){
    return null;
  }

  const activePayments = payments.filter(payment =>
    String(payment?.status || "received").toLowerCase() !== "voided"
  );

  const actual = activePayments.reduce(
    (totals, payment) => {
      totals[quotePaymentClass(payment)] += Number(payment?.amount) || 0;
      return totals;
    },
    {cash:0, credit:0, finance:0}
  );

  let base = payload.paymentPricingBase;

  if(!base || typeof base !== "object"){
    const equipmentTotal = items.reduce(
      (sum, item) => sum + quoteMoney(item.lineTotal),
      0
    );

    const originalTotal = quoteMoney(quote.total);
    const originalTax = quoteMoney(quote.tax);
    const originalPreTax = Math.max(originalTotal - originalTax, 0);

    base = {
      equipmentTotal,
      originalTotal,
      originalTax,
      ancillaryPreTax:Math.max(originalPreTax - equipmentTotal, 0),
      taxRate:
        originalPreTax > 0
          ? originalTax / originalPreTax
          : 0,
      plannedMethod:
        String(payload.plannedPaymentMethod || quote.payment || "")
          .toLowerCase()
          .includes("credit")
          ? "credit"
          : String(payload.plannedPaymentMethod || quote.payment || "")
              .toLowerCase()
              .includes("financ")
            ? "finance"
            : "cash"
    };

    payload.paymentPricingBase = base;
  }

  const remaining = Math.max(
    quoteMoney(base.originalTotal) -
    actual.cash -
    actual.credit -
    actual.finance,
    0
  );

  const plannedMethod =
    ["cash", "credit", "finance"].includes(base.plannedMethod)
      ? base.plannedMethod
      : "cash";

  const planned = {
    cash:actual.cash,
    credit:actual.credit,
    finance:actual.finance
  };

  planned[plannedMethod] += remaining;

  let paymentMethod = "cash";

  if(planned.credit > 0 && planned.cash > 0){
    paymentMethod = "split";
  }else if(planned.credit > 0 && planned.cash <= 0){
    paymentMethod = "credit";
  }else if(planned.finance > 0 && planned.cash <= 0 && planned.credit <= 0){
    /* Keep financed orders at their agreed price until a finance program ID is available. */
    return null;
  }

  let equipmentTotal = 0;

  for(const item of items){
    const pricingRequest = new Request(
      "https://internal/customer-pricing",
      {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          brandId,
          sku:String(item.sku || "").trim(),
          quantity:Math.max(Number(item.qty) || 1, 1),
          paymentMethod,
          cashAmount:planned.cash,
          creditAmount:planned.credit,
          taxExempt:quoteMoney(base.taxRate) <= 0
        })
      }
    );

    const pricingResponse = await handleCustomerPricing(
      pricingRequest,
      env,
      {}
    );

    const pricing = await pricingResponse.json().catch(() => ({}));

    if(!pricingResponse.ok || !Number.isFinite(Number(pricing.customerLinePrice))){
      return null;
    }

    item.repricedLineTotal = Number(pricing.customerLinePrice);
    equipmentTotal += Number(pricing.customerLinePrice);
  }

  const preTax = equipmentTotal + quoteMoney(base.ancillaryPreTax);
  const tax = Math.round(preTax * quoteMoney(base.taxRate) * 100) / 100;
  const total = Math.round((preTax + tax) * 100) / 100;
  const adjustment = Math.round(
    (total - quoteMoney(base.originalTotal)) * 100
  ) / 100;

  payload.paymentMethodPriceAdjustment = adjustment;
  payload.repricedEquipmentTotal = equipmentTotal;
  payload.repricedTax = tax;
  payload.repricedTotal = total;
  payload.actualPaymentMix = actual;

  return {equipmentTotal, tax, total, adjustment};
}

async function recordQuotePayment(
  request,
  env,
  corsHeaders
){
  const data =
    await request.json()
      .catch(() => ({}));

  const quoteId =
    Number(data.quoteId);

  const amount =
    Number(data.amount);

  const paymentMethod =
    String(data.paymentMethod || "").trim();

  const receivedBy =
    String(data.receivedBy || "").trim();

  if(
    !Number.isInteger(quoteId) ||
    quoteId <= 0 ||
    !Number.isFinite(amount) ||
    amount <= 0 ||
    !paymentMethod ||
    !receivedBy
  ){
    return Response.json(
      {
        error:
          "Amount, payment method, and received by are required."
      },
      {
        status:400,
        headers:corsHeaders
      }
    );
  }

  const quote =
    await env.QUOTES_DB.prepare(`
      SELECT
        id,
        configurator,
        payment,
        total,
        tax,
        status,
        payload_json
      FROM quotes
      WHERE id = ?
      LIMIT 1
    `).bind(
      quoteId
    ).first();

  if(!quote){
    return Response.json(
      {
        error:"Quote or order not found."
      },
      {
        status:404,
        headers:corsHeaders
      }
    );
  }

  let payload = {};

  try{
    payload =
      JSON.parse(
        quote.payload_json || "{}"
      );
  }catch(_error){
    payload = {};
  }

  const payments =
    Array.isArray(payload.payments)
      ? payload.payments
      : [];

  const previousReceived =
    payments
      .filter(payment =>
        String(
          payment.status || "received"
        ).toLowerCase() !== "voided"
      )
      .reduce(
        (total, payment) =>
          total +
          (
            Number(payment.amount) ||
            0
          ),
        0
      );

  const newTotalReceived =
    previousReceived + amount;

  const payment = {
    id:
      "PAY-" +
      Date.now() +
      "-" +
      crypto.randomUUID()
        .slice(0, 8),

    date:
      String(data.paymentDate || "")
        .trim() ||
      new Date()
        .toISOString()
        .slice(0, 10),

    amount,

    methodKey:
      String(data.paymentMethodKey || "")
        .trim(),

    method:
      paymentMethod,

    cardType:
      String(data.cardType || "")
        .trim(),

    reference:
      String(data.reference || "")
        .trim(),

    receivedBy,

    status:"received",

    recordedAt:
      new Date().toISOString()
  };

  payments.push(payment);

  const locked = lockedQuoteAmounts(quote, payload);
  const orderTotal = locked.total;

  if(
    orderTotal > 0 &&
    newTotalReceived > orderTotal + 0.009
  ){
    payments.pop();

    return Response.json(
      {error:"Payment exceeds the remaining balance."},
      {status:400, headers:corsHeaders}
    );
  }

  const balanceDue =
    Math.max(
      orderTotal -
      newTotalReceived,
      0
    );

  const newStatus =
    orderTotal > 0 &&
    balanceDue <= 0.009
      ? "Sold"
      : "Ordered";

  payload.payments =
    payments;

  payload.amountReceived =
    newTotalReceived;

  payload.balanceDue =
    balanceDue;

  clearLegacyPaymentRepricing(payload);

  await env.QUOTES_DB.prepare(`
    UPDATE quotes
    SET
      status = ?,
      tax = ?,
      total = ?,
      payload_json = ?
    WHERE id = ?
  `).bind(
    newStatus,
    `$${locked.tax.toFixed(2)}`,
    `$${locked.total.toFixed(2)}`,
    JSON.stringify(payload),
    quoteId
  ).run();

  return Response.json(
    {
      ok:true,
      status:newStatus,
      payment,
      totalReceived:newTotalReceived,
      balanceDue,
      paymentMethodPriceAdjustment:0
    },
    {
      headers:{
        ...corsHeaders,
        "Cache-Control":"no-store"
      }
    }
  );
}

async function voidQuotePayment(
  request,
  env,
  corsHeaders
){
  const data = await request.json()
    .catch(() => ({}));

  const quoteId = Number(data.quoteId);
  const paymentId = String(data.paymentId || "").trim();

  if(
    !Number.isInteger(quoteId) ||
    quoteId <= 0 ||
    !paymentId
  ){
    return Response.json(
      {error:"A valid quote and payment are required."},
      {status:400, headers:corsHeaders}
    );
  }

  const quote = await env.QUOTES_DB.prepare(`
    SELECT id, configurator, payment, total, tax, status, payload_json
    FROM quotes
    WHERE id = ?
    LIMIT 1
  `).bind(quoteId).first();

  if(!quote){
    return Response.json(
      {error:"Quote or order not found."},
      {status:404, headers:corsHeaders}
    );
  }

  let payload = {};

  try{
    payload = JSON.parse(quote.payload_json || "{}");
  }catch(_error){
    payload = {};
  }

  const payments = Array.isArray(payload.payments)
    ? payload.payments
    : [];

  const payment = payments.find(item =>
    String(item?.id || "") === paymentId
  );

  if(!payment){
    return Response.json(
      {error:"Payment record not found."},
      {status:404, headers:corsHeaders}
    );
  }

  if(String(payment.status || "received").toLowerCase() === "voided"){
    return Response.json(
      {error:"Payment is already voided."},
      {status:409, headers:corsHeaders}
    );
  }

  payment.status = "voided";
  payment.voidedAt = new Date().toISOString();

  const totalReceived = payments
    .filter(item =>
      String(item?.status || "received").toLowerCase() !== "voided"
    )
    .reduce(
      (sum, item) => sum + (Number(item?.amount) || 0),
      0
    );

  const locked = lockedQuoteAmounts(quote, payload);
  const orderTotal = locked.total;

  const balanceDue = Math.max(orderTotal - totalReceived, 0);
  const newStatus =
    orderTotal > 0 && balanceDue <= 0.009
      ? "Sold"
      : "Ordered";

  payload.payments = payments;
  payload.amountReceived = totalReceived;
  payload.balanceDue = balanceDue;
  clearLegacyPaymentRepricing(payload);

  await env.QUOTES_DB.prepare(`
    UPDATE quotes
    SET status = ?, tax = ?, total = ?, payload_json = ?
    WHERE id = ?
  `).bind(
    newStatus,
    `$${locked.tax.toFixed(2)}`,
    `$${locked.total.toFixed(2)}`,
    JSON.stringify(payload),
    quoteId
  ).run();

  return Response.json(
    {
      ok:true,
      status:newStatus,
      payment,
      totalReceived,
      balanceDue,
      paymentMethodPriceAdjustment:0
    },
    {
      headers:{
        ...corsHeaders,
        "Cache-Control":"no-store"
      }
    }
  );
}

async function updateQuoteStatus(request, env, corsHeaders) {
  const data = await request.json();

  await env.QUOTES_DB.prepare(`
    UPDATE quotes
    SET status = ?
    WHERE id = ?
  `).bind(
    data.status || "Open",
    data.id
  ).run();

  return Response.json(
    { ok: true },
    { headers: corsHeaders }
  );
}

function formatDate(value){
  if(!value) return "";

  const d = new Date(value);

  if(isNaN(d.getTime())) return String(value);

  return d.toLocaleString("en-US", {
    month: "2-digit",
    day: "2-digit",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit"
  });
}

async function addQuoteNote(request, env, corsHeaders) {
  const data = await request.json();

  await env.QUOTES_DB.prepare(`
    INSERT INTO quote_notes (
      quote_id,
      created_at,
      salesperson,
      note
    ) VALUES (?, ?, ?, ?)
  `).bind(
    data.quoteId,
    new Date().toISOString(),
    data.salesperson || "",
    data.note || ""
  ).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

async function updateQuoteCustomer(
  request,
  env,
  corsHeaders
){

  try{

    const data = await request.json();
    const quoteId = Number(data.id);

    if(!Number.isInteger(quoteId) || quoteId <= 0){

      return Response.json(
        {
          error: "A valid quote ID is required."
        },
        {
          status: 400,
          headers: corsHeaders
        }
      );
    }

    const existing =
      await env.QUOTES_DB.prepare(`
        SELECT payload_json
        FROM quotes
        WHERE id = ?
        LIMIT 1
      `)
      .bind(quoteId)
      .first();

    if(!existing){

      return Response.json(
        {
          error: "Quote or sales order not found."
        },
        {
          status: 404,
          headers: corsHeaders
        }
      );
    }

    let payload = {};

    try{

      payload = JSON.parse(
        existing.payload_json || "{}"
      );

    }catch(error){

      payload = {};
    }

    payload.customerDetails = {

      customer:
        String(data.customer || "").trim(),

      business:
        String(data.business || "").trim(),

      phone:
        String(data.phone || "").trim(),

      altPhone:
        String(data.altPhone || "").trim(),

      email:
        String(data.email || "").trim(),

      address:
        String(data.address || "").trim()
    };

    await env.QUOTES_DB.prepare(`
      UPDATE quotes
      SET
        customer = ?,
        business = ?,
        phone = ?,
        alt_phone = ?,
        email = ?,
        address = ?,
        payload_json = ?
      WHERE id = ?
    `)
    .bind(
      payload.customerDetails.customer,
      payload.customerDetails.business,
      payload.customerDetails.phone,
      payload.customerDetails.altPhone,
      payload.customerDetails.email,
      payload.customerDetails.address,
      JSON.stringify(payload),
      quoteId
    )
    .run();

    return Response.json(
      {
        ok: true
      },
      {
        headers: {
          ...corsHeaders,
          "Cache-Control": "no-store"
        }
      }
    );

  }catch(error){

    console.error(
      "Quote customer update failed:",
      error
    );

    return Response.json(
      {
        error: "Unable to update customer information."
      },
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Cache-Control": "no-store"
        }
      }
    );
  }
}

async function updateQuoteCustomerNote(
  request,
  env,
  corsHeaders
){

  try{

    const data = await request.json();
    const quoteId = Number(data.id);

    if(
      !Number.isInteger(quoteId) ||
      quoteId <= 0
    ){

      return Response.json(
        {
          error: "A valid quote ID is required."
        },
        {
          status: 400,
          headers: corsHeaders
        }
      );
    }

    const existing =
      await env.QUOTES_DB.prepare(`
        SELECT payload_json
        FROM quotes
        WHERE id = ?
        LIMIT 1
      `)
      .bind(quoteId)
      .first();

    if(!existing){

      return Response.json(
        {
          error:
            "Quote or sales order not found."
        },
        {
          status: 404,
          headers: corsHeaders
        }
      );
    }

    let payload = {};

    try{

      payload = JSON.parse(
        existing.payload_json || "{}"
      );

    }catch(error){

      payload = {};
    }

    payload.customerNote =
      String(data.customerNote || "")
      .trim()
      .slice(0, 2000);

    await env.QUOTES_DB.prepare(`
      UPDATE quotes
      SET payload_json = ?
      WHERE id = ?
    `)
    .bind(
      JSON.stringify(payload),
      quoteId
    )
    .run();

    return Response.json(
      {
        ok: true
      },
      {
        headers: {
          ...corsHeaders,
          "Cache-Control": "no-store"
        }
      }
    );

  }catch(error){

    console.error(
      "Customer note update failed:",
      error
    );

    return Response.json(
      {
        error:
          "Unable to update customer note."
      },
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Cache-Control": "no-store"
        }
      }
    );
  }
}

async function updateQuoteFollowUp(request, env, corsHeaders) {
  const data = await request.json();

  await env.QUOTES_DB.prepare(`
    UPDATE quotes
    SET follow_up_date = ?
    WHERE id = ?
  `).bind(
    data.followUpDate || "",
    data.id
  ).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

async function updateOnlineOrder(request, env, corsHeaders) {

  const contentType =
    String(request.headers.get("Content-Type") || "").toLowerCase();

  if (!contentType.includes("application/json")) {
    return Response.json(
      { error: "JSON request required." },
      {
        status: 415,
        headers: corsHeaders
      }
    );
  }

  let data;

  try {
    data = await request.json();
  } catch {
    return Response.json(
      { error: "Invalid request." },
      {
        status: 400,
        headers: corsHeaders
      }
    );
  }

  const orderId =
    Number(data.orderId || 0);

  const status =
    String(data.status || "")
      .trim()
      .toUpperCase();

  const trackingNumber =
    String(data.trackingNumber || "")
      .trim()
      .slice(0, 100);

  const internalNotes =
    String(data.internalNotes || "")
      .trim()
      .slice(0, 2000);

  const allowedStatuses = new Set([
    "PENDING_PAYMENT",
    "PAID",
    "PROCESSING",
    "READY_FOR_PICKUP",
    "SHIPPED",
    "COMPLETED",
    "CANCELLED"
  ]);

  if (!Number.isInteger(orderId) || orderId <= 0) {
    return Response.json(
      { error: "A valid order ID is required." },
      {
        status: 400,
        headers: corsHeaders
      }
    );
  }

  if (!allowedStatuses.has(status)) {
    return Response.json(
      { error: "Invalid order status." },
      {
        status: 400,
        headers: corsHeaders
      }
    );
  }

   /*
    Before an unpaid order is marked CANCELLED,
    expire its Stripe Checkout Session so the
    old payment link can no longer be used.
  */

  const existingOrder =
    await env.QUOTES_DB.prepare(`
      SELECT
        id,
        order_number,
        checkout_token,
        stripe_session_id,
        payment_status,
        status
      FROM online_orders
      WHERE id = ?
      LIMIT 1
    `)
    .bind(orderId)
    .first();

  if(!existingOrder){
    return Response.json(
      {
        error:
          "Online order was not found."
      },
      {
        status:404,
        headers:corsHeaders
      }
    );
  }

  let checkoutExpired = false;

  if(
    status === "CANCELLED" &&
    String(
      existingOrder.payment_status || ""
    ).toUpperCase() !== "PAID" &&
    String(
      existingOrder.stripe_session_id || ""
    ).trim()
  ){

    const orderNumber =
      String(
        existingOrder.order_number || ""
      ).trim();

    const checkoutToken =
      String(
        existingOrder.checkout_token || ""
      ).trim();

    if(!orderNumber || !checkoutToken){
      return Response.json(
        {
          error:
            "This order cannot be safely cancelled because its checkout credentials are incomplete."
        },
        {
          status:409,
          headers:corsHeaders
        }
      );
    }

    let expireResponse;

    try{

      expireResponse =
        await env.STRIPE_WORKER.fetch(
          new Request(
            "https://stripe-worker.internal/online-order-checkout-expire",
            {
              method:"POST",

              headers:{
                "Content-Type":
                  "application/json"
              },

              body:
                JSON.stringify({
                  orderNumber,
                  checkoutToken
                })
            }
          )
        );

    }catch(error){

      console.log(
        "Stripe Checkout expiration request failed:",
        error
      );

      return Response.json(
        {
          error:
            "Unable to contact Stripe to cancel this Checkout Session."
        },
        {
          status:502,
          headers:corsHeaders
        }
      );
    }

    let expireData = {};

    try{
      expireData =
        await expireResponse.json();
    }catch{
      expireData = {};
    }

    if(!expireResponse.ok){

      console.log(
        "Stripe Checkout expiration rejected:",
        expireData
      );

      return Response.json(
        {
          error:
            expireData.error ||
            "Stripe Checkout could not be cancelled."
        },
        {
          status:502,
          headers:corsHeaders
        }
      );
    }

    checkoutExpired =
      Boolean(
        expireData.expired ||
        expireData.alreadyExpired
      );
  }

  const result = await env.QUOTES_DB.prepare(`
    UPDATE online_orders
    SET
      status = ?,
      tracking_number = ?,
      internal_notes = ?,
      updated_at = ?
    WHERE id = ?
  `).bind(
    status,
    trackingNumber,
    internalNotes,
    new Date().toISOString(),
    orderId
  ).run();

  if (!result.meta || Number(result.meta.changes || 0) < 1) {
    return Response.json(
      { error: "Online order was not found." },
      {
        status: 404,
        headers: corsHeaders
      }
    );
  }

  return Response.json(
    {
  ok: true,
  orderId,
  status,
  trackingNumber,
  internalNotes,
  checkoutExpired
},
    {
      headers: corsHeaders
    }
  );
}

async function handleOnlineOrderDetail(env, orderId) {

  const order = await env.QUOTES_DB.prepare(`
    SELECT
      id,
      order_number,
      created_at,
      updated_at,
      status,
      payment_status,

      first_name,
      last_name,
      address_line1,
      address_line2,
      city,
      state,
      zip,
      phone,
      email,

      sku,
      product_name,
      quantity,
      item_price,

      fulfillment,
      pickup_location,
      carrier,
      service,
      shipping_amount,
      shipping_zip,
      estimated_transit_days,

      subtotal,
      tax,
      total,

      terms_version,
      terms_text,
      terms_accepted,
      terms_accepted_at,

      stripe_session_id,
      stripe_payment_intent,
      paid_at,
      paid_email_sent_at,

      tracking_number,
      internal_notes

    FROM online_orders
    WHERE id = ?
    LIMIT 1
  `).bind(orderId).first();

  if (!order) {
    return new Response(`
      <!doctype html>
      <html>
      <head>
        <title>Order Not Found</title>
      </head>
      <body style="font-family:Arial;margin:20px;">
        <h1>Order Not Found</h1>
        <p>
          <a href="/online-orders">&larr; Back to Online Orders</a>
        </p>
      </body>
      </html>
    `, {
      status: 404,
      headers: {
        "Content-Type": "text/html"
      }
    });
  }

  const customerName =
    `${order.first_name || ""} ${order.last_name || ""}`.trim();

  const customerAddress = [
    order.address_line1,
    order.address_line2,
    [order.city, order.state, order.zip]
      .filter(Boolean)
      .join(" ")
  ]
    .filter(Boolean)
    .join("\n");

  const fulfillment =
    String(order.fulfillment || "").toUpperCase() === "SHIP"
      ? `${order.carrier || ""} ${order.service || ""}`.trim() || "Shipping"
      : order.pickup_location
        ? `Pickup - ${order.pickup_location}`
        : order.fulfillment || "";

  const money = value =>
    Number(value || 0).toFixed(2);

  const paymentColor =
    String(order.payment_status || "").toUpperCase() === "PAID"
      ? "#1f7a3a"
      : "#b26a00";

  const termsAccepted =
    Number(order.terms_accepted || 0) === 1
      ? "ACCEPTED"
      : "NOT ACCEPTED";

  return new Response(`
    <!doctype html>
    <html>

    <head>
      <title>${escapeHtml(order.order_number)} - Online Order</title>

      <style>
        body{
          font-family:Arial;
          margin:20px;
          background:#f4f4f4;
          color:#111;
        }

        h1{
          margin-bottom:6px;
        }

        h2{
          margin-top:0;
          font-size:19px;
        }

        .nav{
          margin-bottom:18px;
        }

        .nav a{
          display:inline-block;
          margin-right:14px;
          font-weight:bold;
          color:#111;
        }

        .grid{
          display:grid;
          grid-template-columns:repeat(auto-fit,minmax(300px,1fr));
          gap:16px;
          margin-top:16px;
        }

        .card{
          background:#fff;
          border:1px solid #ddd;
          border-radius:12px;
          padding:16px;
          box-shadow:0 2px 8px rgba(0,0,0,.04);
        }

        .label{
          color:#666;
          font-size:12px;
          font-weight:bold;
          text-transform:uppercase;
          margin-top:12px;
        }

        .value{
          margin-top:3px;
          font-size:15px;
          white-space:pre-wrap;
        }

        .total{
          font-size:26px;
          font-weight:900;
        }

        .payment-status{
          color:${paymentColor};
          font-weight:900;
          font-size:20px;
        }

        table{
          width:100%;
          border-collapse:collapse;
        }

        td{
          padding:7px 4px;
          border-bottom:1px solid #eee;
        }

        td:last-child{
          text-align:right;
          font-weight:bold;
        }

        .terms{
          white-space:pre-wrap;
          font-size:13px;
          line-height:1.45;
        }
      </style>
    </head>

    <body>

      <div class="nav">
        <a href="/dashboard">Dashboard</a>
        <a href="/quotes">Quote Manager</a>
        <a href="/online-orders">&larr; Online Orders</a>
      </div>

      <h1>${escapeHtml(order.order_number)}</h1>

      <div>
        Created:
        ${escapeHtml(formatDate(order.created_at))}
      </div>

      <div class="grid">

        <div class="card">

          <h2>Customer</h2>

          <div class="label">Name</div>
          <div class="value">${escapeHtml(customerName)}</div>

          <div class="label">Address</div>
          <div class="value">${escapeHtml(customerAddress)}</div>

          <div class="label">Phone</div>
          <div class="value">${escapeHtml(order.phone)}</div>

          <div class="label">Email</div>
          <div class="value">${escapeHtml(order.email)}</div>

        </div>

        <div class="card">

          <h2>Product</h2>

          <div class="label">Product</div>
          <div class="value">${escapeHtml(order.product_name)}</div>

          <div class="label">SKU</div>
          <div class="value">${escapeHtml(order.sku)}</div>

          <div class="label">Quantity</div>
          <div class="value">${escapeHtml(order.quantity)}</div>

          <div class="label">Item Price</div>
          <div class="value">$${escapeHtml(money(order.item_price))}</div>

        </div>

        <div class="card">

          <h2>Fulfillment</h2>

          <div class="label">Method</div>
          <div class="value">${escapeHtml(fulfillment)}</div>

          <div class="label">Shipping Charge</div>
          <div class="value">$${escapeHtml(money(order.shipping_amount))}</div>

          <div class="label">Shipping ZIP</div>
          <div class="value">${escapeHtml(order.shipping_zip)}</div>

          <div class="label">Estimated Transit</div>
          <div class="value">${
            order.estimated_transit_days
              ? `${escapeHtml(order.estimated_transit_days)} day(s)`
              : ""
          }</div>

          <div class="label">Tracking Number</div>
          <div class="value">${escapeHtml(order.tracking_number)}</div>

        </div>

        <div class="card">

          <h2>Payment</h2>

          <table>
            <tr>
              <td>Item</td>
              <td>$${escapeHtml(money(order.item_price))}</td>
            </tr>

            <tr>
              <td>Shipping</td>
              <td>$${escapeHtml(money(order.shipping_amount))}</td>
            </tr>

            <tr>
              <td>Subtotal</td>
              <td>$${escapeHtml(money(order.subtotal))}</td>
            </tr>

            <tr>
              <td>Sales Tax</td>
              <td>$${escapeHtml(money(order.tax))}</td>
            </tr>

            <tr>
              <td>Total</td>
              <td class="total">$${escapeHtml(money(order.total))}</td>
            </tr>
          </table>

          <div class="label">Payment Status</div>
          <div class="payment-status">
            ${escapeHtml(order.payment_status)}
          </div>

          <div class="label">Paid</div>
          <div class="value">${escapeHtml(formatDate(order.paid_at))}</div>

        </div>

        <div class="card">

          <h2>Order Management</h2>

          <div class="label">Order Status</div>

          <select
            id="orderStatus"
            style="
              width:100%;
              padding:10px;
              margin-top:4px;
              border:1px solid #bbb;
              border-radius:6px;
              font-size:15px;
              box-sizing:border-box;
            "
          >
            <option
              value="PENDING_PAYMENT"
              ${order.status === "PENDING_PAYMENT" ? "selected" : ""}
            >
              Pending Payment
            </option>

            <option
              value="PAID"
              ${order.status === "PAID" ? "selected" : ""}
            >
              Paid
            </option>

            <option
              value="PROCESSING"
              ${order.status === "PROCESSING" ? "selected" : ""}
            >
              Processing
            </option>

            <option
              value="READY_FOR_PICKUP"
              ${order.status === "READY_FOR_PICKUP" ? "selected" : ""}
            >
              Ready for Pickup
            </option>

            <option
              value="SHIPPED"
              ${order.status === "SHIPPED" ? "selected" : ""}
            >
              Shipped
            </option>

            <option
              value="COMPLETED"
              ${order.status === "COMPLETED" ? "selected" : ""}
            >
              Completed
            </option>

            <option
              value="CANCELLED"
              ${order.status === "CANCELLED" ? "selected" : ""}
            >
              Cancelled
            </option>
          </select>

          <div class="label">Tracking Number</div>

          <input
            id="trackingNumber"
            type="text"
            maxlength="100"
            value="${escapeHtml(order.tracking_number)}"
            style="
              width:100%;
              padding:10px;
              margin-top:4px;
              border:1px solid #bbb;
              border-radius:6px;
              font-size:15px;
              box-sizing:border-box;
            "
          >

          <div class="label">Internal Notes</div>

          <textarea
            id="internalNotes"
            maxlength="2000"
            style="
              width:100%;
              min-height:90px;
              padding:10px;
              margin-top:4px;
              border:1px solid #bbb;
              border-radius:6px;
              font-size:15px;
              box-sizing:border-box;
              resize:vertical;
            "
          >${escapeHtml(order.internal_notes)}</textarea>

          <button
            id="saveOrderBtn"
            type="button"
            style="
              margin-top:14px;
              padding:11px 16px;
              background:#111;
              color:#fff;
              border:0;
              border-radius:6px;
              font-weight:bold;
              cursor:pointer;
            "
          >
            Save Order Update
          </button>

          <div
            id="orderUpdateResult"
            style="
              margin-top:10px;
              font-weight:bold;
            "
          ></div>

          <div class="label">Last Updated</div>
          <div class="value">${escapeHtml(formatDate(order.updated_at))}</div>

        </div>

        <div class="card">

          <h2>Stripe</h2>

          <div class="label">Checkout Session</div>
          <div class="value">${escapeHtml(order.stripe_session_id)}</div>

          <div class="label">Payment Intent</div>
          <div class="value">${escapeHtml(order.stripe_payment_intent)}</div>

          <div class="label">Paid Email Sent</div>
          <div class="value">
            ${escapeHtml(formatDate(order.paid_email_sent_at))}
          </div>

        </div>

      </div>

      <div class="card" style="margin-top:16px;">

        <h2>Customer Terms</h2>

        <div class="label">Terms Status</div>
        <div class="value">
          <strong>${escapeHtml(termsAccepted)}</strong>
        </div>

        <div class="label">Accepted At</div>
        <div class="value">
          ${escapeHtml(formatDate(order.terms_accepted_at))}
        </div>

        <div class="label">Terms Version</div>
        <div class="value">${escapeHtml(order.terms_version)}</div>

        <details style="margin-top:14px;">
          <summary style="cursor:pointer;font-weight:bold;">
            View Accepted Terms
          </summary>

          <div class="terms">
            ${escapeHtml(order.terms_text)}
          </div>
        </details>

       </div>

      <script>
        document
          .getElementById("saveOrderBtn")
          .addEventListener("click", async function() {

            const button = this;

            const result =
              document.getElementById("orderUpdateResult");

            result.textContent = "";

            button.disabled = true;
            button.textContent = "Saving...";

            try {

              const response =
                await fetch("/online-order-update", {
                  method: "POST",

                  headers: {
                    "Content-Type": "application/json"
                  },

                  body: JSON.stringify({
                    orderId: ${Number(order.id)},

                    status:
                      document.getElementById("orderStatus").value,

                    trackingNumber:
                      document.getElementById("trackingNumber").value,

                    internalNotes:
                      document.getElementById("internalNotes").value
                  })
                });

              const data =
                await response.json();

              if (!response.ok) {
                result.style.color = "#b00020";
                result.textContent =
                  data.error || "Could not update order.";
                return;
              }

              result.style.color = "#1f7a3a";
              result.textContent =
                "Order updated successfully.";

              setTimeout(function() {
                window.location.reload();
              }, 500);

            } catch (error) {

              result.style.color = "#b00020";
              result.textContent =
                "Could not update order.";

            } finally {

              button.disabled = false;
              button.textContent = "Save Order Update";

            }

          });
      </script>

    </body>
    </html>
  `, {
    headers: {
      "Content-Type": "text/html"
    }
  });
}

async function handleOnlineOrders(env, request) {

  await ensureOnlineOrdersTable(env);

  const url = new URL(request.url);
  const q = String(url.searchParams.get("q") || "").trim();

  const orderId =
    Number(url.searchParams.get("id") || 0);

  if (Number.isInteger(orderId) && orderId > 0) {
    return handleOnlineOrderDetail(env, orderId);
  }

  let result;

  if (q) {

    const like = `%${q}%`;

    result = await env.QUOTES_DB.prepare(`
      SELECT
        id,
        order_number,
        created_at,
        status,
        payment_status,
        first_name,
        last_name,
        phone,
        email,
        sku,
        product_name,
        fulfillment,
        pickup_location,
        carrier,
        service,
        shipping_amount,
        subtotal,
        tax,
        total,
        paid_at
      FROM online_orders
      WHERE
        order_number LIKE ?
        OR first_name LIKE ?
        OR last_name LIKE ?
        OR phone LIKE ?
        OR email LIKE ?
        OR sku LIKE ?
        OR product_name LIKE ?
      ORDER BY id DESC
      LIMIT 100
    `).bind(
      like,
      like,
      like,
      like,
      like,
      like,
      like
    ).all();

  } else {

    result = await env.QUOTES_DB.prepare(`
      SELECT
        id,
        order_number,
        created_at,
        status,
        payment_status,
        first_name,
        last_name,
        phone,
        email,
        sku,
        product_name,
        fulfillment,
        pickup_location,
        carrier,
        service,
        shipping_amount,
        subtotal,
        tax,
        total,
        paid_at
      FROM online_orders
      ORDER BY id DESC
      LIMIT 100
    `).all();

  }

  const rows = (result.results || []).map(order => {

    const customer =
      `${order.first_name || ""} ${order.last_name || ""}`.trim();

    const fulfillment =
      String(order.fulfillment || "").toUpperCase() === "SHIP"
        ? `${order.carrier || ""} ${order.service || ""}`.trim() || "Ship"
        : order.pickup_location
          ? `Pickup - ${order.pickup_location}`
          : order.fulfillment || "";

    const total =
      Number(order.total || 0).toFixed(2);

    const paymentColor =
      String(order.payment_status || "").toUpperCase() === "PAID"
        ? "#1f7a3a"
        : "#b26a00";

    return `
      <tr>
        <td>
  <a href="/online-orders?id=${encodeURIComponent(order.id)}">
    ${escapeHtml(order.order_number)}
  </a>
</td>
        <td>${escapeHtml(formatDate(order.created_at))}</td>
        <td>${escapeHtml(customer)}</td>
        <td>${escapeHtml(order.phone)}</td>
        <td>${escapeHtml(order.product_name)}</td>
        <td>${escapeHtml(order.sku)}</td>
        <td>${escapeHtml(fulfillment)}</td>
        <td>$${escapeHtml(total)}</td>
        <td style="font-weight:bold;color:${paymentColor};">
          ${escapeHtml(order.payment_status)}
        </td>
        <td>${escapeHtml(order.status)}</td>
      </tr>
    `;

  }).join("");

  return new Response(`
    <!doctype html>
    <html>
    <head>
      <title>West End Power Online Orders</title>

      <style>
        body{
          font-family:Arial;
          margin:20px;
          background:#f4f4f4;
          color:#111;
        }

        h1{
          margin-bottom:8px;
        }

        .nav{
          margin-bottom:18px;
        }

        .nav a{
          display:inline-block;
          margin-right:14px;
          font-weight:bold;
          color:#111;
        }

        .card{
          background:#fff;
          border:1px solid #ddd;
          border-radius:12px;
          padding:16px;
          box-shadow:0 2px 8px rgba(0,0,0,.04);
        }

        form{
          display:flex;
          gap:8px;
          margin:12px 0 18px 0;
        }

        input{
          padding:10px;
          font-size:15px;
          width:420px;
          max-width:100%;
          border:1px solid #bbb;
          border-radius:6px;
        }

        button{
          padding:10px 14px;
          font-weight:bold;
          background:#111;
          color:#fff;
          border:0;
          border-radius:6px;
          cursor:pointer;
        }

        table{
          width:100%;
          border-collapse:collapse;
          background:#fff;
        }

        th,
        td{
          border:1px solid #ddd;
          padding:8px;
          font-size:13px;
          text-align:left;
          vertical-align:top;
        }

        th{
          background:#111;
          color:#fff;
        }

        tr:nth-child(even){
          background:#fafafa;
        }
      </style>
    </head>

    <body>

      <h1>West End Power Online Orders</h1>

      <div class="nav">
        <a href="/dashboard">Dashboard</a>
        <a href="/quotes">Quote Manager</a>
        <a href="/online-orders">Online Orders</a>
      </div>

      <div class="card">

        <form method="GET" action="/online-orders">
          <input
            name="q"
            value="${escapeHtml(q)}"
            placeholder="Search order #, customer, phone, email, SKU, or product"
          >

          <button type="submit">Search</button>

          <a href="/online-orders"
             style="padding:10px 14px;">
            Clear
          </a>
        </form>

        <p>
          ${
            q
              ? `Search results for: <strong>${escapeHtml(q)}</strong>`
              : "Most recent 100 online orders"
          }
        </p>

        <table>
          <tr>
            <th>Order #</th>
            <th>Date</th>
            <th>Customer</th>
            <th>Phone</th>
            <th>Product</th>
            <th>SKU</th>
            <th>Fulfillment</th>
            <th>Total</th>
            <th>Payment</th>
            <th>Order Status</th>
          </tr>

          ${
            rows ||
            `<tr>
              <td colspan="10">No online orders found.</td>
            </tr>`
          }

        </table>

      </div>

    </body>
    </html>
  `, {
    headers: {
      "Content-Type": "text/html"
    }
  });
}

async function handleDashboard(env) {
  const statusRows = await env.QUOTES_DB.prepare(`
    SELECT status, COUNT(*) AS count
    FROM quotes
    GROUP BY status
  `).all();

  const today = new Date().toISOString().slice(0, 10);

  const followups = await env.QUOTES_DB.prepare(`
    SELECT
      id,
      quote_number,
      customer,
      phone,
      selected_tool,
      total,
      status,
      follow_up_date
    FROM quotes
    WHERE follow_up_date <= ?
      AND status NOT IN ('Sold','Lost','Cancelled')
    ORDER BY follow_up_date ASC, id DESC
    LIMIT 25
  `).bind(today).all();

  const recent = await env.QUOTES_DB.prepare(`
    SELECT
      id,
      quote_number,
      created_at,
      salesperson,
      customer,
      selected_tool,
      total,
      status
    FROM quotes
    ORDER BY id DESC
    LIMIT 10
  `).all();

  const statusCards = (statusRows.results || []).map(r => `
    <a
      class="card stat"
      href="/quotes?status=${encodeURIComponent(r.status || "Unknown")}"
    >
      <div class="label">${escapeHtml(r.status || "Unknown")}</div>
      <div class="num">${escapeHtml(r.count)}</div>
    </a>
  `).join("");

  const followupRows = (followups.results || []).map(q => `
    <tr>
      <td><a href="/quotes?id=${encodeURIComponent(q.id)}">${escapeHtml(q.quote_number)}</a></td>
      <td>${escapeHtml(q.follow_up_date)}</td>
      <td>${escapeHtml(q.customer)}</td>
      <td>${escapeHtml(q.phone)}</td>
      <td>${escapeHtml(q.selected_tool)}</td>
      <td>${escapeHtml(q.total)}</td>
      <td>${escapeHtml(q.status)}</td>
    </tr>
  `).join("");

  const recentRows = (recent.results || []).map(q => `
    <tr>
      <td><a href="/quotes?id=${encodeURIComponent(q.id)}">${escapeHtml(q.quote_number)}</a></td>
      <td>${escapeHtml(formatDate(q.created_at))}</td>
      <td>${escapeHtml(q.salesperson)}</td>
      <td>${escapeHtml(q.customer)}</td>
      <td>${escapeHtml(q.selected_tool)}</td>
      <td>${escapeHtml(q.total)}</td>
      <td>${escapeHtml(q.status)}</td>
    </tr>
  `).join("");

  return new Response(`
    <!doctype html>
    <html>
    <head>
      <title>West End Power Dashboard</title>
      <style>
        body{font-family:Arial;margin:20px;background:#f4f4f4;color:#111;}
        h1{margin-bottom:8px;}
        .nav a{display:inline-block;margin-right:10px;font-weight:bold;color:#111;}
        .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin:18px 0;}
        .card{background:#fff;border:1px solid #ddd;border-radius:12px;padding:16px;box-shadow:0 2px 8px rgba(0,0,0,.04);}
        .stat{
          display:block;
          color:#111;
          text-decoration:none;
          transition:transform .15s ease,box-shadow .15s ease;
        }
        .stat:hover{
          transform:translateY(-2px);
          box-shadow:0 5px 14px rgba(0,0,0,.12);
        }
        .stat .label{font-size:14px;color:#555;}
        .stat .num{font-size:34px;font-weight:900;margin-top:6px;}
        table{width:100%;border-collapse:collapse;background:#fff;margin-top:10px;}
        th,td{border:1px solid #ddd;padding:8px;font-size:13px;text-align:left;}
        th{background:#111;color:#fff;}
        tr:nth-child(even){background:#fafafa;}
      </style>
    </head>
    <body>
      <h1>West End Power Sales Dashboard</h1>

      <div class="nav">
        <a href="/quotes">Quote Manager</a>
        <a href="/quotes?status=Ordered">Sales Orders</a>
        <a href="/quotes?status=Sold">Sold Orders</a>
        <a href="/online-orders">Online Orders</a>
        <a href="/dashboard">Dashboard</a>
      </div>

      <div class="stats">
        ${statusCards || `<div class="card stat"><div class="label">Quotes</div><div class="num">0</div></div>`}
      </div>

      <div class="card">
        <h2>Follow-Ups Due</h2>
        <table>
          <tr>
            <th>Quote #</th>
            <th>Follow-Up</th>
            <th>Customer</th>
            <th>Phone</th>
            <th>Equipment</th>
            <th>Total</th>
            <th>Status</th>
          </tr>
          ${followupRows || `<tr><td colspan="7">No follow-ups due.</td></tr>`}
        </table>
      </div>

      <div class="card">
        <h2>Recent Quotes</h2>
        <table>
          <tr>
            <th>Quote #</th>
            <th>Date</th>
            <th>Salesperson</th>
            <th>Customer</th>
            <th>Equipment</th>
            <th>Total</th>
            <th>Status</th>
          </tr>
          ${recentRows || `<tr><td colspan="7">No recent quotes.</td></tr>`}
        </table>
      </div>
    </body>
    </html>
  `, {
    headers: { "Content-Type": "text/html" }
  });
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
