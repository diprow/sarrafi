(function(){
"use strict";

/* refuse to run inside a frame (clickjacking protection, since GitHub Pages can't send headers) */
if (window.top !== window.self) { document.documentElement.innerHTML = ""; return; }

const CFG = window.LEDGER_CONFIG || {};
const ARRIVED_FOR_RECOVERY = /type=recovery/.test(location.hash) || /type=recovery/.test(location.search);
let recovering = ARRIVED_FOR_RECOVERY;
const TABLE = "ledger_docs";
const VAULT_ID = "_vault";
const KDF_ITER = 600000;
const IDLE_MS = 10 * 60 * 1000;

const $ = id => document.getElementById(id);
const fmtInt = new Intl.NumberFormat("en-US", {maximumFractionDigits:0});
const fmtDec = new Intl.NumberFormat("en-US", {maximumFractionDigits:2});
const rid = () => { const a = crypto.getRandomValues(new Uint8Array(9)); return Array.from(a, b => b.toString(36).padStart(2,"0")).join(""); };
const isoDay = t => { const d = new Date(t); d.setMinutes(d.getMinutes()-d.getTimezoneOffset()); return d.toISOString().slice(0,10); };
const today = () => isoDay(Date.now());

/* ---------- Supabase ---------- */
let sb = null, uid = null, email = "";
function makeClient(){
  return window.supabase.createClient(CFG.supabaseUrl, CFG.supabaseKey, {
    auth: { storage: window.sessionStorage, persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
  });
}

/* ---------- crypto: AES-256-GCM, key from PBKDF2-SHA256 ---------- */
const te = new TextEncoder(), td = new TextDecoder();
const b64 = buf => { const a = new Uint8Array(buf); let s = ""; for (let i=0;i<a.length;i+=0x8000) s += String.fromCharCode.apply(null, a.subarray(i,i+0x8000)); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
let key = null;
async function deriveKey(pass, salt, iter){
  const base = await crypto.subtle.importKey("raw", te.encode(pass.normalize("NFKC")), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt, iterations:iter, hash:"SHA-256"}, base, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
}
const aadFor = docId => te.encode("diapay|" + uid + "|" + docId);
async function seal(obj, docId, k = key){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv, additionalData:aadFor(docId)}, k, te.encode(JSON.stringify(obj)));
  return {v:1, iv:b64(iv), ct:b64(ct)};
}
async function unseal(body, docId, k = key){
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(body.iv), additionalData:aadFor(docId)}, k, unb64(body.ct));
  return JSON.parse(td.decode(pt));
}

/* ---------- numbers ---------- */
function normalizeDigits(s){
  return String(s||"")
    .replace(/[۰-۹]/g, c => String(c.charCodeAt(0)-0x06F0))
    .replace(/[٠-٩]/g, c => String(c.charCodeAt(0)-0x0660))
    .replace(/[٫]/g,".").replace(/[,،٬\s]/g,"");
}
function parseNum(s){ const t = normalizeDigits(s); if (!t || !/^\d*\.?\d*$/.test(t)) return NaN; return parseFloat(t); }
function groupString(raw){
  const [i,d] = raw.split(".");
  const g = (i||"").replace(/^0+(?=\d)/,"").replace(/\B(?=(\d{3})+(?!\d))/g,",");
  return d !== undefined ? (g||"0") + "." + d : g;
}
function liveFormat(el){
  const pos = el.selectionStart ?? el.value.length;
  const before = normalizeDigits(el.value.slice(0,pos)).replace(/[^\d.]/g,"").length;
  let raw = normalizeDigits(el.value).replace(/[^\d.]/g,"");
  const fd = raw.indexOf("."); if (fd >= 0) raw = raw.slice(0,fd+1) + raw.slice(fd+1).replace(/\./g,"");
  const out = groupString(raw); el.value = out;
  let seen = 0, p = 0; while (p < out.length && seen < before){ if (/[\d.]/.test(out[p])) seen++; p++; }
  try { el.setSelectionRange(p,p); } catch(e) {}
}
const money = n => fmtInt.format(Math.round(n));
const dec = n => fmtDec.format(n);

/* ---------- state ---------- */
function freshAccount(name, role){ return {id:"acc-"+rid(), name, role: role === "seller" ? "seller" : "buyer", deals:[], pays:[], order:Date.now()}; }
const isSeller = a => a && a.role === "seller";
/* wording for each side: buyer = we pay euro, they pay toman; seller = they give euro, we pay toman */
function W(a){
  const n = a.name;
  return isSeller(a) ? {
    role:"فروشنده", roleHint:"یورو از او می‌گیرید، تومان به او می‌دهید",
    tabDeal:`یورو از ${n}`, tabPay:`تومان به ${n}`,
    owe:`شما باید به ${n} بپردازید`, credit:`${n} به شما بدهکار است`,
    stOpen:"مانده‌ی قابل پرداخت", stCredit:"پرداخت اضافه از طرف شما",
    statEur:`یوروی دریافتی از ${n}`, statPaid:`پرداختی به ${n}`,
    colEur:["یوروی دریافتی",`Euro received from ${n}`], colPaid:["پرداختی تومان",`Paid in Toman to ${n}`], colDue:["مانده",`You should pay ${n}`],
    payKind:"پرداختی", payAmt:"مبلغ پرداختی (تومان)", payBtn:"ثبت پرداختی", payEdit:"در حال ویرایش یک پرداختی", payErr:"مبلغ پرداختی را وارد کنید.",
    empty:`اولین یوروی دریافتی از ${n} یا تومانی که به او پرداختید را از بالا ثبت کنید.`,
    csv:[`Euro received from ${n}`,`Pieces paid in Toman to ${n}`,`You should pay ${n} in Toman`]
  } : {
    role:"خریدار", roleHint:"یورو به او می‌دهید، تومان از او می‌گیرید",
    tabDeal:`یورو به ${n}`, tabPay:`تومان از ${n}`,
    owe:`${n} باید بپردازد`, credit:`شما به ${n} بدهکارید`,
    stOpen:"مانده‌ی قابل دریافت", stCredit:"پرداخت اضافه از طرف مشتری",
    statEur:`یوروی پرداختی به ${n}`, statPaid:`دریافتی از ${n}`,
    colEur:["یوروی پرداختی",`Euro paid to ${n}`], colPaid:["دریافتی تومان",`Paid in Toman by ${n}`], colDue:["مانده",`${n} should pay`],
    payKind:"دریافتی", payAmt:"مبلغ دریافتی (تومان)", payBtn:"ثبت دریافتی", payEdit:"در حال ویرایش یک دریافتی", payErr:"مبلغ دریافتی را وارد کنید.",
    empty:`اولین معامله‌ی یورو یا دریافتی تومانی ${n} را از بالا ثبت کنید.`,
    csv:[`Euro paid to ${n}`,`Pieces paid in Toman by ${n}`,`${n} should pay in Toman`]
  };
}
let state = {accounts:[], active:null};
let dirty = new Set(), removed = new Set(), unreadable = 0;
let editing = null, pendingDelete = null, flashId = null, mode = "deal";
let addingAccount = false, renaming = false;
let saveTimer = null, flushing = false, flushAgain = false, vaultDoc = null;

function ensureAccount(){
  if (!state.accounts.length){ const a = freshAccount("Sedghi"); state.accounts.push(a); dirty.add(a.id); }
  if (!state.accounts.find(a => a.id === state.active)) state.active = state.accounts[0].id;
}
const acc = () => state.accounts.find(a => a.id === state.active);
function setStatus(kind, text){ $("dot").className = "dot " + (kind||""); $("statusText").textContent = text; }

function commit(id){ if (id) dirty.add(id); render(); scheduleSave(); }
function scheduleSave(){ if (!key) return; setStatus("busy","در حال ذخیره…"); clearTimeout(saveTimer); saveTimer = setTimeout(flush, 500); }
async function flush(){
  if (!key || !sb) return;
  if (flushing){ flushAgain = true; return; }
  flushing = true;
  const ids = [...dirty]; dirty.clear(); const dels = [...removed]; removed.clear();
  try {
    const rows = [];
    for (const id of ids){
      const a = state.accounts.find(x => x.id === id); if (!a) continue;
      rows.push({user_id:uid, doc_id:id, body: await seal({name:a.name, role:a.role||"buyer", order:a.order||0, deals:a.deals, pays:a.pays}, id)});
    }
    if (rows.length){
      const { error } = await sb.from(TABLE).upsert(rows, {onConflict:"user_id,doc_id"});
      if (error) throw error;
    }
    if (dels.length){
      const { error } = await sb.from(TABLE).delete().eq("user_id", uid).in("doc_id", dels);
      if (error) throw error;
    }
    setStatus("ok","رمزنگاری و ذخیره شد");
  } catch(e) {
    ids.forEach(i => dirty.add(i)); dels.forEach(i => removed.add(i));
    if (e && (e.status === 401 || e.code === "PGRST301" || /JWT/i.test(e.message||""))){ setStatus("err","نشست منقضی شده؛ دوباره وارد شوید"); return; }
    if (e && e.code === "42501"){ setStatus("err","اجازه‌ی نوشتن در دیتابیس را ندارید"); return; }
    setStatus("err","ذخیره نشد؛ دوباره تلاش می‌شود");
    setTimeout(() => { if (key) flush(); }, 3000 + Math.random()*2000);
  } finally {
    flushing = false;
    if (flushAgain){ flushAgain = false; if (dirty.size || removed.size) flush(); }
  }
}
window.addEventListener("beforeunload", e => { if (key && (dirty.size || removed.size || flushing)){ e.preventDefault(); e.returnValue = ""; } });

/* ---------- math ---------- */
function sortKey(r){ return r.date || isoDay(r.t||0); }
function ledgerRows(a){
  const rows = [...a.deals.map(d => ({kind:"deal", ...d, total:Math.round(d.eur*d.rate)})), ...a.pays.map(p => ({kind:"pay", ...p}))]
    .sort((x,y) => sortKey(x).localeCompare(sortKey(y)) || (x.t||0)-(y.t||0));
  let bal = 0; for (const r of rows){ bal += r.kind === "deal" ? r.total : -r.rial; r.bal = bal; }
  return rows;
}
function totals(a){
  const eur = a.deals.reduce((s,d) => s+d.eur, 0), total = a.deals.reduce((s,d) => s+Math.round(d.eur*d.rate), 0), paid = a.pays.reduce((s,p) => s+p.rial, 0);
  return {eur, total, paid, due:total-paid, avgRate: eur ? total/eur : 0};
}

/* ---------- dom ---------- */
function el(tag, attrs, ...kids){
  const n = document.createElement(tag);
  for (const k in (attrs||{})){
    const v = attrs[k];
    if (k === "class") n.className = v; else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids){ if (c == null) continue; n.append(c.nodeType ? c : document.createTextNode(c)); }
  return n;
}
function gcd(a,b){ return b ? gcd(b, a%b) : a; }
function guilloche(){
  const NS = "http://www.w3.org/2000/svg", s = document.createElementNS(NS,"svg");
  s.setAttribute("viewBox","-200 -200 400 400"); s.setAttribute("class","guilloche"); s.setAttribute("aria-hidden","true");
  for (const L of [{R:150,r:52,d:70,c:"rgba(201,172,120,.55)"},{R:110,r:37,d:46,c:"rgba(242,238,227,.22)"}]){
    let dd = ""; const loops = L.r/gcd(L.R,L.r), N = Math.round(110*loops), k = (L.R-L.r)/L.r;
    for (let i=0;i<=N;i++){ const t = i/N*Math.PI*2*loops;
      const x = (L.R-L.r)*Math.cos(t)+L.d*Math.cos(k*t), y = (L.R-L.r)*Math.sin(t)-L.d*Math.sin(k*t);
      dd += (i?"L":"M") + x.toFixed(2) + " " + y.toFixed(2); }
    const p = document.createElementNS(NS,"path"); p.setAttribute("d",dd); p.setAttribute("fill","none"); p.setAttribute("stroke",L.c); p.setAttribute("stroke-width",".6"); s.append(p);
  }
  return s;
}
const G = guilloche();
$("crest").prepend(guilloche());
const serialOf = id => { let h = 0; for (const c of id) h = (h*31 + c.charCodeAt(0)) >>> 0; return "DP · " + String(h%1e6).padStart(6,"0"); };

/* ---------- render ---------- */
function renderAccounts(){
  const nav = $("accounts"); nav.replaceChildren();
  for (const a of [...state.accounts].sort((x,y) => (x.order||0)-(y.order||0))){
    nav.append(el("button",{class:"acc",type:"button","aria-current":String(a.id===state.active),onclick:() => { state.active = a.id; editing = null; pendingDelete = null; renaming = false; clearDeal(true); clearPay(); render(); }}, a.name, el("span",{class:"role"+(isSeller(a)?" seller":"")}, W(a).role)));
  }
  if (addingAccount){
    const inp = el("input",{placeholder:"نام مشتری"});
    let role = "buyer";
    const bBuy = el("button",{type:"button","aria-pressed":"true",title:"یورو به او می‌دهید، تومان از او می‌گیرید"},"خریدار");
    const bSell = el("button",{type:"button","aria-pressed":"false",title:"یورو از او می‌گیرید، تومان به او می‌دهید"},"فروشنده");
    const setRole = r => { role = r; bBuy.setAttribute("aria-pressed", String(r==="buyer")); bSell.setAttribute("aria-pressed", String(r==="seller")); inp.focus(); };
    bBuy.addEventListener("click", () => setRole("buyer")); bSell.addEventListener("click", () => setRole("seller"));
    const done = () => { const v = inp.value.trim(); addingAccount = false; if (v){ const a = freshAccount(v, role); state.accounts.push(a); state.active = a.id; commit(a.id); } else render(); };
    inp.addEventListener("keydown", e => { if (e.key==="Enter"){ e.preventDefault(); done(); } if (e.key==="Escape"){ addingAccount=false; render(); } });
    nav.append(el("span",{class:"acc-input"}, inp, el("span",{class:"role-pick"}, bBuy, bSell), el("button",{class:"link",type:"button",onclick:done},"افزودن")));
    setTimeout(() => inp.focus(), 0);
  } else nav.append(el("button",{class:"acc add",type:"button",onclick:() => { addingAccount = true; render(); }},"+ مشتری جدید"));

  const a = acc(), tools = el("span",{class:"acc-tools"});
  if (renaming){
    const inp = el("input",{value:a.name, class:"rename"});
    const save = () => { const v = inp.value.trim(); renaming = false; if (v && v !== a.name){ a.name = v; commit(a.id); } else render(); };
    inp.addEventListener("keydown", e => { if (e.key==="Enter"){ e.preventDefault(); save(); } if (e.key==="Escape"){ renaming=false; render(); } });
    tools.append(inp, el("button",{class:"link",type:"button",onclick:save},"ذخیره"));
    setTimeout(() => { inp.focus(); inp.select(); }, 0);
  } else tools.append(el("button",{class:"link",type:"button",onclick:() => { renaming = true; render(); }},"تغییر نام"));
  tools.append(el("button",{class:"link",type:"button",title:W(a).roleHint,onclick:() => {
    a.role = isSeller(a) ? "buyer" : "seller"; commit(a.id);
  }}, `نوع: ${W(a).role} — تغییر به ${isSeller(a) ? "خریدار" : "فروشنده"}`));
  const k = "acc:" + a.id;
  tools.append(el("button",{class:"link"+(pendingDelete===k?" danger":""),type:"button",onclick:() => {
    if (pendingDelete !== k){ pendingDelete = k; render(); return; }
    pendingDelete = null; state.accounts = state.accounts.filter(x => x.id !== a.id); removed.add(a.id); dirty.delete(a.id); ensureAccount(); commit();
  }}, pendingDelete === k ? `حذف کامل حساب ${a.name}؟ دوباره بزنید` : "حذف مشتری"));
  nav.append(tools);
}

function renderNote(){
  const a = acc(), t = totals(a), credit = t.due < 0, zero = t.due === 0 && (a.deals.length || a.pays.length);
  const w = W(a);
  const label = credit ? w.credit : w.owe;
  const stateTxt = zero ? "حساب تسویه است" : credit ? w.stCredit : (t.due > 0 ? w.stOpen : "هنوز معامله‌ای ثبت نشده");
  $("note").replaceChildren(
    G,
    el("div",null,
      el("div",{class:"who"}, el("span",null,a.name + " · " + w.role), el("span",{class:"serial"},serialOf(a.id))),
      el("div",{class:"label"},label),
      el("div",{class:"amount"}, el("span",{class:"num"},money(Math.abs(t.due))), el("span",{class:"unit"},"تومان")),
      el("span",{class:"state"},stateTxt)
    ),
    el("div",{class:"stats"},
      el("div",{class:"stat"},el("span",null,w.statEur),el("b",{class:"num"},"€ "+dec(t.eur))),
      el("div",{class:"stat"},el("span",null,"جمع تومانی معاملات"),el("b",{class:"num"},money(t.total))),
      el("div",{class:"stat"},el("span",null,w.statPaid),el("b",{class:"num"},money(t.paid))),
      el("div",{class:"stat"},el("span",null,"میانگین نرخ"),el("b",{class:"num"},t.eur ? money(t.avgRate) : "—"))
    )
  );
}

function renderEntry(){
  const a = acc();
  const w = W(a);
  $("tabDealTxt").textContent = w.tabDeal;
  $("tabPayTxt").textContent = w.tabPay;
  $("payAmtLbl").textContent = w.payAmt;
  $("payEditFlag").textContent = w.payEdit;
  $("tabDeal").setAttribute("aria-selected", String(mode==="deal"));
  $("tabPay").setAttribute("aria-selected", String(mode==="pay"));
  $("dealPanel").hidden = mode !== "deal"; $("payPanel").hidden = mode !== "pay";
  $("dealPanel").classList.toggle("editing", editing?.kind === "deal");
  $("payPanel").classList.toggle("editing", editing?.kind === "pay");
  $("dealBtn").textContent = editing?.kind === "deal" ? "ذخیره تغییرات" : "ثبت معامله";
  $("payBtn").textContent = editing?.kind === "pay" ? "ذخیره تغییرات" : w.payBtn;
  $("dealCancel").hidden = editing?.kind !== "deal"; $("payCancel").hidden = editing?.kind !== "pay";
  updatePreview();
}
function updatePreview(){
  const e = parseNum($("fEur").value), r = parseNum($("fRate").value);
  $("fPreview").textContent = (e > 0 && r > 0) ? money(e*r) + "  تومان" : "—";
}

function renderLedger(){
  const a = acc(), rows = ledgerRows(a), t = totals(a), box = $("ledger");
  $("csvBtn").hidden = !rows.length;
  $("count").textContent = rows.length ? `${rows.length} ردیف` : "";
  if (!rows.length){
    box.replaceChildren(el("div",{class:"blank"}, el("b",null,"دفتر خالی است"), W(a).empty));
    return;
  }
  const h = (fa,en,cls) => el("th",{class:cls||""}, fa, en ? el("small",null,en) : null);
  const w = W(a);
  const head = el("tr",null,
    h("شرح"),
    h(w.colEur[0],w.colEur[1],"n"),
    h("نرخ","Rate","n"),
    h("مبلغ تومانی","Total Toman to be paid","n"),
    h(w.colPaid[0],w.colPaid[1],"n"),
    h(w.colDue[0],w.colDue[1],"n"),
    h("توضیح"), el("th")
  );
  const body = el("tbody");
  for (const r of rows){
    const isDeal = r.kind === "deal", k = r.kind + ":" + r.id;
    body.append(el("tr",{class: r.id === flashId ? "flash" : ""},
      el("td",null, el("span",{class:"kind "+r.kind}, el("i",null,isDeal?"€":"ت"), el("span",null, isDeal?"معامله":w.payKind, r.date ? el("span",{class:"date"},r.date) : null))),
      isDeal ? el("td",{class:"n"},"€ "+dec(r.eur)) : el("td",{class:"n muted"},"·"),
      isDeal ? el("td",{class:"n"},dec(r.rate)) : el("td",{class:"n muted"},"·"),
      isDeal ? el("td",{class:"n"},money(r.total)) : el("td",{class:"n muted"},"·"),
      !isDeal ? el("td",{class:"n"},money(r.rial)) : el("td",{class:"n muted"},"·"),
      el("td",{class:"n bal "+(r.bal>0?"pos":r.bal<0?"neg":"")},money(r.bal)),
      el("td",{class:"note-c"},r.note||""),
      el("td",null, el("div",{class:"acts"},
        el("button",{class:"link",type:"button",onclick:() => startEdit(r)},"ویرایش"),
        el("button",{class:"link"+(pendingDelete===k?" confirm":""),type:"button",onclick:() => {
          if (pendingDelete !== k){ pendingDelete = k; render(); return; }
          pendingDelete = null;
          if (isDeal) a.deals = a.deals.filter(x => x.id !== r.id); else a.pays = a.pays.filter(x => x.id !== r.id);
          if (editing && editing.id === r.id){ editing = null; clearDeal(true); clearPay(); }
          commit(a.id);
        }}, pendingDelete === k ? "حذف شود؟" : "حذف")
      ))
    ));
  }
  const foot = el("tfoot",null, el("tr",null,
    el("td",null,"جمع"),
    el("td",{class:"n"},"€ "+dec(t.eur)),
    el("td",{class:"n",title:"میانگین وزنی"}, t.eur ? dec(t.avgRate) : "—"),
    el("td",{class:"n"},money(t.total)),
    el("td",{class:"n"},money(t.paid)),
    el("td",{class:"n bal "+(t.due>0?"pos":t.due<0?"neg":"")},money(t.due)),
    el("td",{class:"note-c"}, t.eur ? "نرخ: میانگین وزنی" : ""), el("td")
  ));
  box.replaceChildren(el("table",null, el("thead",null,head), body, foot));
  flashId = null;
}

function render(){ if (!key) return; ensureAccount(); renderAccounts(); renderNote(); renderEntry(); renderLedger(); }

/* ---------- editing ---------- */
function setMode(m){ if (editing && editing.kind !== m){ editing = null; clearDeal(true); clearPay(); } mode = m; pendingDelete = null; render(); }
function startEdit(r){
  pendingDelete = null; editing = {kind:r.kind, id:r.id}; mode = r.kind;
  if (r.kind === "deal"){ $("fEur").value = groupString(String(r.eur)); $("fRate").value = groupString(String(r.rate)); $("fDealDate").value = r.date||""; $("fDealNote").value = r.note||""; }
  else { $("fRial").value = groupString(String(r.rial)); $("fPayDate").value = r.date||""; $("fPayNote").value = r.note||""; }
  render();
  (r.kind === "deal" ? $("fEur") : $("fRial")).focus();
  document.querySelector(".entry").scrollIntoView({behavior:"smooth", block:"center"});
}
function clearDeal(rateToo){ $("fEur").value = ""; if (rateToo) $("fRate").value = ""; $("fDealNote").value = ""; $("fDealDate").value = ""; $("dealErr").textContent = ""; }
function clearPay(){ $("fRial").value = ""; $("fPayNote").value = ""; $("fPayDate").value = ""; $("payErr").textContent = ""; }

$("tabDeal").addEventListener("click", () => setMode("deal"));
$("tabPay").addEventListener("click", () => setMode("pay"));
["fEur","fRate","fRial"].forEach(id => $(id).addEventListener("input", e => { liveFormat(e.target); if (id !== "fRial") updatePreview(); }));
$("dealPanel").addEventListener("submit", e => {
  e.preventDefault();
  const a = acc(), eur = parseNum($("fEur").value), rate = parseNum($("fRate").value);
  if (!(eur > 0)){ $("dealErr").textContent = "مبلغ یورو را وارد کنید."; $("fEur").focus(); return; }
  if (!(rate > 0)){ $("dealErr").textContent = "نرخ هر یورو را وارد کنید."; $("fRate").focus(); return; }
  const data = {eur, rate, date:$("fDealDate").value||"", note:$("fDealNote").value.trim()};
  if (editing?.kind === "deal"){ const d = a.deals.find(x => x.id === editing.id); if (d) Object.assign(d, data); flashId = editing.id; editing = null; clearDeal(true); }
  else { const id = rid(); a.deals.push({id, t:Date.now(), ...data}); flashId = id; clearDeal(false); }
  commit(a.id); $("fEur").focus();
});
$("payPanel").addEventListener("submit", e => {
  e.preventDefault();
  const a = acc(), rial = parseNum($("fRial").value);
  if (!(rial > 0)){ $("payErr").textContent = W(a).payErr; $("fRial").focus(); return; }
  const data = {rial, date:$("fPayDate").value||"", note:$("fPayNote").value.trim()};
  if (editing?.kind === "pay"){ const p = a.pays.find(x => x.id === editing.id); if (p) Object.assign(p, data); flashId = editing.id; editing = null; }
  else { const id = rid(); a.pays.push({id, t:Date.now(), ...data}); flashId = id; }
  clearPay(); commit(a.id); $("fRial").focus();
});
$("dealCancel").addEventListener("click", () => { editing = null; clearDeal(true); render(); });
$("payCancel").addEventListener("click", () => { editing = null; clearPay(); render(); });
document.addEventListener("keydown", e => { if (e.key === "Escape" && pendingDelete){ pendingDelete = null; render(); } });

/* ---------- CSV export / import ---------- */
$("csvBtn").addEventListener("click", () => {
  if (!key) return;
  const a = acc(), rows = ledgerRows(a), t = totals(a), q = v => '"' + String(v ?? "").replace(/"/g,'""') + '"';
  const w = W(a);
  const L = [["Date","Type",w.csv[0],"Rate (Toman)","Total Toman to be paid",w.csv[1],w.csv[2],"Note"].map(q).join(",")];
  for (const r of rows) L.push([r.date||"", r.kind==="deal"?"Deal":"Payment", r.kind==="deal"?r.eur:"", r.kind==="deal"?r.rate:"", r.kind==="deal"?r.total:"", r.kind==="pay"?r.rial:"", r.bal, r.note||""].map(q).join(","));
  L.push(["","Total",t.eur,t.eur?Math.round(t.avgRate*100)/100:"",t.total,t.paid,t.due,""].map(q).join(","));
  const blob = new Blob(["\uFEFF" + L.join("\r\n")], {type:"text/csv;charset=utf-8"});
  const url = URL.createObjectURL(blob);
  const link = el("a",{href:url, download:`${a.name}-${today()}.csv`}); document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
});
function parseCSV(text){
  const rows = []; let row = [], cur = "", q = false;
  for (let i=0;i<text.length;i++){
    const c = text[i];
    if (q){ if (c === '"'){ if (text[i+1] === '"'){ cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ","){ row.push(cur); cur = ""; }
    else if (c === "\n"){ row.push(cur.replace(/\r$/,"")); rows.push(row); row = []; cur = ""; }
    else cur += c;
  }
  if (cur.length || row.length){ row.push(cur.replace(/\r$/,"")); rows.push(row); }
  return rows.filter(r => r.some(x => x.trim() !== ""));
}
$("csvIn").addEventListener("change", async e => {
  const file = e.target.files && e.target.files[0]; e.target.value = "";
  if (!file || !key) return;
  try {
    if (file.size > 5*1024*1024) throw new Error("big");
    const rows = parseCSV((await file.text()).replace(/^\uFEFF/,""));
    if (rows.length < 2) throw new Error("empty");
    const hdr = rows[0].map(s => s.trim());
    const hasType = hdr[1] === "Type";
    const euroCol = hasType ? 2 : 1;
    const m = /^Euro (paid to|received from) (.+)$/.exec(hdr[euroCol] || "");
    if (!m) throw new Error("format");
    const importRole = m[1] === "received from" ? "seller" : "buyer";
    m[1] = m[2];
    let name = m[1].trim(), n = 2;
    while (state.accounts.some(x => x.name === name)) name = `${m[1].trim()} ${n++}`;
    const a = freshAccount(name, importRole); let t = Date.now();
    for (const r of rows.slice(1)){
      const kind = hasType ? r[1] : "";
      if (/^total$/i.test((kind||r[0]||"").trim())) continue;
      const date = /^\d{4}-\d{2}-\d{2}$/.test((r[0]||"").trim()) ? r[0].trim() : "";
      const note = (r[hasType ? 7 : 6] || "").slice(0,500);
      const eur = parseNum(r[euroCol]), rate = parseNum(r[euroCol+1]), paid = parseNum(r[euroCol+3]);
      if (eur > 0 && rate > 0) a.deals.push({id:rid(), t:t++, eur, rate, date, note});
      else if (paid > 0) a.pays.push({id:rid(), t:t++, rial:paid, date, note});
    }
    if (!a.deals.length && !a.pays.length) throw new Error("empty");
    state.accounts.push(a); state.active = a.id; commit(a.id);
    setStatus("ok", `${a.deals.length + a.pays.length} ردیف وارد حساب «${a.name}» شد`);
  } catch(err) {
    setStatus("err", "فایل CSV قابل خواندن نبود؛ از فایلی استفاده کنید که خود دفتر خروجی گرفته");
  }
});

/* ---------- screens: login → claim → vault ---------- */
let fails = 0, waitUntil = 0;
function strength(s){
  let n = 0; if (s.length >= 10) n++; if (s.length >= 14) n++;
  const kinds = [/[a-z]/,/[A-Z]/,/\d/,/[^A-Za-z0-9]/].filter(r => r.test(s)).length;
  if (kinds >= 2) n++; if (kinds >= 3) n++;
  return Math.min(4, n);
}
function screen(sub){
  $("app").hidden = true; $("lock").hidden = false;
  $("lockSub").textContent = sub;
  const f = $("lockForm"); f.replaceChildren(); f.hidden = false; f.onsubmit = null;
  return f;
}
function showLoading(msg){ screen(msg || "در حال بارگذاری…").hidden = true; }
function showError(msg, withLogout){
  const f = screen("مشکلی پیش آمد");
  f.append(el("p",{class:"warn"},msg), el("button",{class:"btn",type:"button",onclick:() => location.reload()},"تلاش دوباره"));
  if (withLogout) f.append(el("button",{class:"switch",type:"button",onclick:logout},"خروج از این حساب"));
}

function showLogin(msg, isOk){
  const f = screen("ورود به دفتر");
  const em = el("input",{type:"email",autocomplete:"username",required:true});
  const pw = el("input",{type:"password",autocomplete:"current-password",required:true});
  const err = el("div",{class:"err"}), btn = el("button",{class:"btn",type:"submit"},"ورود");
  if (msg) f.append(el("p",{class: isOk ? "ok" : "warn"}, msg));
  f.append(el("label",null,"ایمیل",em), el("label",null,"رمز ورود",pw), btn, err,
    el("button",{class:"switch",type:"button",onclick:() => showForgot(em.value.trim())},"رمز ورود را فراموش کرده‌اید؟"),
    el("button",{class:"switch",type:"button",onclick:showSignup},"حساب ندارید؟ ساخت حساب"));
  f.onsubmit = async e => {
    e.preventDefault(); err.textContent = ""; btn.disabled = true; btn.textContent = "در حال ورود…";
    const { error } = await sb.auth.signInWithPassword({email:em.value.trim(), password:pw.value});
    pw.value = "";
    if (error){
      btn.disabled = false; btn.textContent = "ورود";
      err.textContent = /confirm/i.test(error.message) ? "ایمیل هنوز تأیید نشده؛ لینک تأیید را از ایمیلتان باز کنید." : "ایمیل یا رمز ورود اشتباه است.";
      return;
    }
    await afterLogin();
  };
  setTimeout(() => em.focus(), 0);
}
function showSignup(){
  const f = screen("ساخت حساب");
  const em = el("input",{type:"email",autocomplete:"username",required:true});
  const pw = el("input",{type:"password",autocomplete:"new-password",required:true,minlength:"10"});
  const err = el("div",{class:"err"}), btn = el("button",{class:"btn",type:"submit"},"ساخت حساب");
  f.append(
    el("p",{class:"hint"},"فقط ایمیلی که مدیر سایت است می‌تواند دفتر را باز کند، و فقط اولین نفر."),
    el("label",null,"ایمیل",em), el("label",null,"رمز ورود (حداقل ۱۰ کاراکتر)",pw), btn, err,
    el("button",{class:"switch",type:"button",onclick:() => showLogin()},"حساب دارید؟ ورود"));
  f.onsubmit = async e => {
    e.preventDefault(); err.textContent = "";
    if (pw.value.length < 10){ err.textContent = "رمز ورود باید حداقل ۱۰ کاراکتر باشد."; return; }
    btn.disabled = true; btn.textContent = "در حال ساخت…";
    const { data, error } = await sb.auth.signUp({email:em.value.trim(), password:pw.value, options:{emailRedirectTo: location.origin + location.pathname}});
    pw.value = "";
    if (error){ btn.disabled = false; btn.textContent = "ساخت حساب"; err.textContent = "ساخت حساب ناموفق بود: " + (error.message || ""); return; }
    if (data.user && Array.isArray(data.user.identities) && data.user.identities.length === 0){
      showLogin("این ایمیل از قبل حساب دارد و رمزش تغییر نکرد. با رمز فعلی وارد شوید، یا از «رمز ورود را فراموش کرده‌اید؟» رمز تازه بگذارید.");
      return;
    }
    if (data.session) await afterLogin();
    else showLogin("حساب ساخته شد. لینک تأیید را از ایمیلتان باز کنید و بعد وارد شوید.", true);
  };
  setTimeout(() => em.focus(), 0);
}

function showForgot(prefill){
  const f = screen("بازیابی رمز ورود");
  const em = el("input",{type:"email",autocomplete:"username",required:true,value:prefill||""});
  const err = el("div",{class:"err"}), btn = el("button",{class:"btn",type:"submit"},"ارسال لینک بازیابی");
  f.append(el("p",{class:"hint"},"یک لینک به ایمیلتان می‌فرستیم. با باز کردنش به همین صفحه برمی‌گردید و رمز ورود تازه می‌گذارید."),
    el("label",null,"ایمیل",em), btn, err,
    el("button",{class:"switch",type:"button",onclick:() => showLogin()},"بازگشت به ورود"));
  f.onsubmit = async e => {
    e.preventDefault(); err.textContent = ""; btn.disabled = true; btn.textContent = "در حال ارسال…";
    const { error } = await sb.auth.resetPasswordForEmail(em.value.trim(), {redirectTo: location.origin + location.pathname});
    if (error){
      btn.disabled = false; btn.textContent = "ارسال لینک بازیابی";
      err.textContent = /rate|limit|seconds/i.test(error.message||"") ? "تعداد درخواست‌ها زیاد بوده؛ کمی بعد دوباره امتحان کنید." : "ارسال ناموفق بود: " + (error.message||"");
      return;
    }
    showLogin("اگر این ایمیل حساب داشته باشد، لینک بازیابی فرستاده شد. پوشه‌ی Spam را هم نگاه کنید.", true);
  };
  setTimeout(() => em.focus(), 0);
}

function showNewLoginPassword(afterwards){
  const f = screen("رمز ورود تازه");
  const p1 = el("input",{type:"password",autocomplete:"new-password"}), p2 = el("input",{type:"password",autocomplete:"new-password"});
  const err = el("div",{class:"err"}), btn = el("button",{class:"btn",type:"submit"},"ذخیره‌ی رمز ورود");
  f.append(el("p",{class:"hint"},"این رمز برای ورود به حساب است و با «رمز دفتر» فرق دارد."),
    el("label",null,"رمز ورود تازه (حداقل ۱۰ کاراکتر)",p1), el("label",null,"تکرار رمز ورود",p2), btn, err);
  if (afterwards) f.append(el("button",{class:"switch",type:"button",onclick:afterwards},"انصراف"));
  f.onsubmit = async e => {
    e.preventDefault(); err.textContent = "";
    if (p1.value.length < 10){ err.textContent = "رمز باید حداقل ۱۰ کاراکتر باشد."; return; }
    if (p1.value !== p2.value){ err.textContent = "دو رمز یکی نیستند."; return; }
    btn.disabled = true; btn.textContent = "در حال ذخیره…";
    const { error } = await sb.auth.updateUser({password:p1.value});
    p1.value = p2.value = "";
    if (error){
      btn.disabled = false; btn.textContent = "ذخیره‌ی رمز ورود";
      err.textContent = /reauthentication|recent/i.test(error.message||"") ? "برای تغییر رمز باید دوباره وارد شوید." : "ذخیره نشد: " + (error.message||"");
      return;
    }
    recovering = false;
    try { history.replaceState(null, "", location.pathname); } catch(x) {}
    if (afterwards) afterwards(); else await afterLogin();
  };
  setTimeout(() => p1.focus(), 0);
}

async function afterLogin(){
  showLoading("در حال بررسی دسترسی…");
  const { data: { user } } = await sb.auth.getUser();
  if (!user){ showLogin(); return; }
  uid = user.id; email = user.email || "";
  const { data: allowed, error } = await sb.rpc("claim_ledger");
  if (error){ showError("ارتباط با دیتابیس برقرار نشد. چند لحظه بعد دوباره امتحان کنید.", true); return; }
  if (!allowed){ showError(`حساب ${email} اجازه‌ی دسترسی به این دفتر را ندارد.`, true); return; }
  const v = await sb.from(TABLE).select("body").eq("user_id", uid).eq("doc_id", VAULT_ID).maybeSingle();
  if (v.error){ showError("خواندن دیتابیس ناموفق بود.", true); return; }
  if (v.data){ vaultDoc = v.data.body; showUnlock(); } else showSetup();
}

function showSetup(){
  const f = screen("ساخت رمز دفتر");
  const p1 = el("input",{type:"password",autocomplete:"off"}), p2 = el("input",{type:"password",autocomplete:"off"});
  const bar = el("i"), ck = el("input",{type:"checkbox"}), err = el("div",{class:"err"});
  const btn = el("button",{class:"btn",type:"submit"},"ساخت رمز و رمزنگاری دفتر");
  p1.addEventListener("input", () => { const s = strength(p1.value); bar.style.width = (s*25) + "%"; bar.style.background = s >= 3 ? "var(--credit)" : s === 2 ? "var(--brass)" : "var(--debt)"; });
  f.append(
    el("p",{class:"hint"},"این رمز جدا از رمز ورود است. همه‌ی اطلاعات قبل از ارسال به دیتابیس، روی همین دستگاه با این رمز قفل می‌شوند و هیچ‌کس بدون آن، حتی با دسترسی به دیتابیس، نمی‌تواند آن‌ها را بخواند."),
    el("label",null,"رمز دفتر (حداقل ۱۰ کاراکتر)",p1,el("span",{class:"meter"},bar)),
    el("label",null,"تکرار رمز دفتر",p2),
    el("p",{class:"warn"},"این رمز هیچ‌جا ذخیره نمی‌شود و قابل بازیابی نیست. اگر فراموشش کنید، اطلاعات دفتر برای همیشه از دست می‌رود. از رمز ورود استفاده نکنید."),
    el("label",{class:"check"},ck,el("span",null,"متوجه شدم و رمز را جای امنی یادداشت کرده‌ام.")),
    btn, err, el("button",{class:"switch",type:"button",onclick:logout},"خروج"));
  f.onsubmit = async e => {
    e.preventDefault(); err.textContent = "";
    if (p1.value.length < 10){ err.textContent = "رمز باید حداقل ۱۰ کاراکتر باشد."; return; }
    if (strength(p1.value) < 2){ err.textContent = "رمز خیلی ساده است؛ ترکیب حروف، عدد و نماد استفاده کنید."; return; }
    if (p1.value !== p2.value){ err.textContent = "دو رمز یکی نیستند."; return; }
    if (!ck.checked){ err.textContent = "لطفاً تیک تأیید را بزنید."; return; }
    btn.disabled = true; btn.textContent = "در حال ساخت کلید…";
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const k = await deriveKey(p1.value, salt, KDF_ITER);
      const body = await seal({check:"diapay-vault", created:Date.now()}, VAULT_ID, k);
      Object.assign(body, {kdf:"PBKDF2-SHA256", iter:KDF_ITER, salt:b64(salt)});
      const { error } = await sb.from(TABLE).insert({user_id:uid, doc_id:VAULT_ID, body});
      if (error) throw error;
      p1.value = p2.value = ""; vaultDoc = body; key = k;
      await openLedger();
    } catch(x) { btn.disabled = false; btn.textContent = "ساخت رمز و رمزنگاری دفتر"; err.textContent = "ساخت دفتر ناموفق بود. دوباره امتحان کنید."; }
  };
  setTimeout(() => p1.focus(), 0);
}

function showUnlock(msg){
  const f = screen(msg || "دفتر قفل است");
  const p = el("input",{type:"password",autocomplete:"off"}), err = el("div",{class:"err"});
  const btn = el("button",{class:"btn",type:"submit"},"باز کردن دفتر");
  f.append(el("p",{class:"who-line"},email), el("label",null,"رمز دفتر",p), btn, err,
    el("button",{class:"switch",type:"button",onclick:() => showNewLoginPassword(() => showUnlock())},"تغییر رمز ورود"),
    el("button",{class:"switch",type:"button",onclick:logout},"خروج از حساب"));
  const tick = () => { const s = Math.ceil((waitUntil - Date.now())/1000); if (s > 0){ btn.disabled = true; btn.textContent = `صبر کنید (${s} ثانیه)`; setTimeout(tick, 500); } else { btn.disabled = false; btn.textContent = "باز کردن دفتر"; } };
  tick();
  f.onsubmit = async e => {
    e.preventDefault(); if (Date.now() < waitUntil || !p.value) return;
    btn.disabled = true; btn.textContent = "در حال باز کردن…"; err.textContent = "";
    let ok = false;
    try {
      const k = await deriveKey(p.value, unb64(vaultDoc.salt), vaultDoc.iter || KDF_ITER);
      const v = await unseal(vaultDoc, VAULT_ID, k);
      if (v.check === "diapay-vault"){ key = k; ok = true; }
    } catch(x) {}
    p.value = "";
    if (ok){ fails = 0; await openLedger(); return; }
    fails++; p.focus(); err.textContent = "رمز دفتر اشتباه است.";
    if (fails >= 3) waitUntil = Date.now() + Math.min(300, 5 * 2 ** (fails-3)) * 1000;
    tick();
  };
  setTimeout(() => p.focus(), 0);
}

const asAccount = (id, v) => ({id, name:String(v.name||"بی‌نام"), role: v.role === "seller" ? "seller" : "buyer", order:Number(v.order)||0,
  deals: Array.isArray(v.deals) ? v.deals.map(x => ({...x})) : [], pays: Array.isArray(v.pays) ? v.pays.map(x => ({...x})) : []});

async function openLedger(){
  showLoading("در حال باز کردن دفتر…");
  const { data, error } = await sb.from(TABLE).select("doc_id, body").eq("user_id", uid).neq("doc_id", VAULT_ID);
  if (error){ key = null; showError("خواندن دفتر از دیتابیس ناموفق بود.", true); return; }
  const accounts = []; unreadable = 0;
  for (const row of data || []){
    try { accounts.push(asAccount(row.doc_id, await unseal(row.body, row.doc_id))); } catch(e) { unreadable++; }
  }
  state = {accounts, active: accounts[0]?.id || null};
  ensureAccount();
  $("lock").hidden = true; $("app").hidden = false;
  render();
  if (unreadable) setStatus("err", `${unreadable} حساب با این رمز باز نشد و دست‌نخورده باقی ماند`);
  else setStatus("ok","رمزنگاری و ذخیره شد");
  if (dirty.size) await flush();
  armIdle();
}

async function lockNow(){
  clearTimeout(saveTimer);
  if (dirty.size || removed.size){ setStatus("busy","در حال ذخیره قبل از قفل…"); await flush(); }
  key = null;
  state = {accounts:[], active:null}; editing = null; pendingDelete = null; addingAccount = false; renaming = false;
  clearDeal(true); clearPay();
  $("ledger").replaceChildren(); $("note").replaceChildren(); $("accounts").replaceChildren();
  if (vaultDoc) showUnlock(); else showLogin();
}
async function logout(){
  if (key) await lockNow();
  key = null; vaultDoc = null; uid = null; email = "";
  try { await sb.auth.signOut(); } catch(e) {}
  try { sessionStorage.clear(); } catch(e) {}
  showLogin("از حساب خارج شدید.", true);
}
$("lockBtn").addEventListener("click", lockNow);
$("logoutBtn").addEventListener("click", logout);

let idleTimer = null;
function armIdle(){ clearTimeout(idleTimer); idleTimer = setTimeout(() => { if (key) lockNow(); }, IDLE_MS); }
["pointerdown","keydown","wheel","touchstart"].forEach(ev => document.addEventListener(ev, () => { if (key) armIdle(); }, {passive:true}));

/* ---------- boot ---------- */
async function boot(){
  showLoading();
  if (!window.isSecureContext || !window.crypto || !crypto.subtle){ showError("این صفحه فقط روی HTTPS و مرورگر به‌روز کار می‌کند."); return; }
  if (!window.supabase || !CFG.supabaseUrl || !CFG.supabaseKey){ showError("فایل‌های برنامه کامل بارگذاری نشدند."); return; }
  sb = makeClient();
  sb.auth.onAuthStateChange(evt => {
    if (evt === "PASSWORD_RECOVERY"){ recovering = true; key = null; showNewLoginPassword(); return; }
    if (evt === "SIGNED_OUT" && (key || vaultDoc)){ key = null; vaultDoc = null; state = {accounts:[], active:null}; showLogin("نشست شما تمام شد؛ دوباره وارد شوید."); }
  });
  const { data: { session } } = await sb.auth.getSession();
  if (recovering){
    if (session) showNewLoginPassword();
    else showLogin("لینک بازیابی منقضی یا نامعتبر است؛ دوباره درخواست بدهید.");
    return;
  }
  if (session) await afterLogin(); else showLogin();
}
boot();
})();
