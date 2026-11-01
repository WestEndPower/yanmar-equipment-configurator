'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8');
function functionSource(name){
  const start=source.indexOf('function '+name+'(');
  assert.ok(start>=0,name);
  const end=source.indexOf('\nfunction ',start+1);
  return source.slice(start,end<0?source.length:end);
}
function context(overrides={}){
  const sandbox={clean:v=>String(v??'').trim(),money:v=>Number(v)||0,
    isTrue:v=>/^(t|true|1)$/i.test(String(v)),configuratorBrandId:()=> 'YANMAR',
    publicProfitProtectionDown:()=>0,currentQuoteTotal:()=>20000,
    fmtMoney:v=>'$'+v.toFixed(2),isDateActive:()=>true,financeProgramFeeIsAllowed:()=>true,
    primaryFinanceItem:()=>({BrandID:'YANMAR',Model:'SA425',Series:'SA425',SKU:'SA425BI-L'}),
    skuOf:t=>t.SKU,bidFleetEngine:()=>null,$:()=>null,
    selectedCustomerFinanceProgram:()=>null,financeRemainingSelected:()=>true,
    cashFullPaymentSelected:()=>false,creditFullPaymentSelected:()=>false,
    cashBalancePaymentSelected:()=>false,creditBalancePaymentSelected:()=>false,
    recordedSalePaymentAmount:()=>0,...overrides};
  vm.createContext(sandbox);
  for(const name of ['financeGroupColumnsForTool','financeProgramFlag','financeBulletinGroupForTool',
    'financeProgramGroupMatches','priceTagMinimumDown','minimumDownForProgram',
    'minimumDownRequirementLabel','monthlyPayment','financeAnalysis','paymentCents',
    'paymentEngine','financingApplies'])vm.runInContext(functionSource(name),sandbox);
  return sandbox;
}
function csvRows(text){
  const rows=[];let row=[],cell='',quoted=false;
  for(let i=0;i<text.length;i++){
    const c=text[i];
    if(c==='"'){if(quoted&&text[i+1]==='"'){cell+='"';i++;}else quoted=!quoted;}
    else if(!quoted&&(c===','||c==='\n')){row.push(cell.trim());cell='';if(c==='\n'){rows.push(row);row=[];}}
    else if(c!=='\r')cell+=c;
  }
  if(cell||row.length){row.push(cell.trim());rows.push(row);}
  const headers=rows.shift().map(h=>h.replace(/^\uFEFF/,''));
  return rows.filter(r=>r.length>1).map(r=>Object.fromEntries(headers.map((h,i)=>[h,r[i]||''])));
}
const programs=csvRows(fs.readFileSync(path.join(__dirname,'../data/finance-programs.csv'),'utf8'));
test('all-Yanmar flag matches across equipment families and keeps brand boundaries',()=>{
  const c=context();
  for(const Model of ['SA223','YT359C','YZ200','BULL']){
    assert.ok(c.financeGroupColumnsForTool({BrandID:'YANMAR',Model}).includes('Group_ALL_YANMAR'));
    assert.ok(!c.financeGroupColumnsForTool({BrandID:'YANMAR',Model}).includes('Group_ALL_STIHL'));
  }
  assert.equal(c.financingApplies({BrandID:'YANMAR',Group_ALL_YANMAR:'T'}),true);
  assert.equal(c.financingApplies({BrandID:'STIHL',Group_ALL_STIHL:'T'}),false);
  assert.equal(c.financeProgramFlag({GROUP_SA425:'T'},'Group_SA425'),true);
  assert.equal(c.financeProgramFlag({GROUP_SA425:'F'},'Group_SA425'),false);
});
test('all 71 published programs retain their dates and all-brand programs qualify',()=>{
  const c=context();assert.equal(programs.length,71);
  for(const p of programs){assert.equal(p.StartDate,'2026-11-01');assert.equal(p.EndDate,'2026-12-31');}
  const all=programs.filter(p=>p.Group_ALL_YANMAR==='T');assert.ok(all.length>0);
  for(const p of all)assert.equal(c.financingApplies(p),true,p.ProgramID);
});
test('the four published down-payment programs calculate 10% and 35% consistently',()=>{
  const c=context();
  const expected={'YA-13-46327':2000,'YA-14-46327':2000,'YA-16-46327':2000,'YA-30-46327':7000};
  const required=programs.filter(p=>Number(p.MinDownPercent)>0||Number(p.MinDownAmount)>0);
  assert.equal(required.length,4);
  for(const p of required){
    assert.equal(c.minimumDownForProgram(p,20000),expected[p.ProgramID]);
    assert.equal(c.priceTagMinimumDown(p,20000),expected[p.ProgramID]);
    assert.equal(c.minimumDownForProgram({...p,MinDownPercent:Number(p.MinDownPercent)*100},20000),expected[p.ProgramID]);
  }
  assert.equal(c.minimumDownForProgram({MinDownPercent:.1},20001),2010);
  assert.equal(c.minimumDownForProgram({MinDownAmount:30000},20000),20000);
  assert.equal(c.minimumDownForProgram({},20000),0);
});
test('cash and credit deposits satisfy required down without being charged twice',()=>{
  const p=programs.find(p=>p.ProgramID==='YA-30-46327');
  for(const [cash,credit,extra,financed] of [[0,0,7000,13000],[2000,1000,4000,13000],[7000,0,0,13000],[8000,0,0,12000]]){
    const c=context({selectedCustomerFinanceProgram:()=>p,$:id=>({value:id==='stihl-cash-payment'?cash:id==='stihl-credit-payment'?credit:''})});
    const split=c.paymentEngine(20000);
    assert.equal(split.requiredExtraDown,extra);assert.equal(split.financeAmount,financed);
    assert.equal(split.amountDueToday+split.financeAmount,20000);
  }
});
test('minimum financed balance accounts for required and optional down payments',()=>{
  const p=programs.find(p=>p.ProgramID==='YA-16-46327');
  assert.equal(context({currentQuoteTotal:()=>16000}).financingApplies(p),false);
  assert.equal(context({currentQuoteTotal:()=>20000}).financingApplies(p),true);
  assert.equal(context({currentQuoteTotal:()=>20000,$:id=>id==='stihl-cash-payment'?{value:6000}:null}).financingApplies(p),false);
});
test('monthly financing uses balance after down plus one customer application fee',()=>{
  const c=context();const p={APR:0,TermMonths:60,ApplicationFee:299};
  const result=c.financeAnalysis(p,13000);
  assert.equal(result.principalFinanced,13299);assert.equal(result.payment,13299/60);
  assert.equal(c.minimumDownRequirementLabel({MinDownPercent:.35}),'35% required');
});
test('all inline application scripts parse',()=>{
  let count=0;
  for(const m of source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)){
    if(/\bsrc=|application\/ld\+json/.test(m[1]))continue;
    new vm.Script(m[2]);count++;
  }
  assert.ok(count>0);
});
