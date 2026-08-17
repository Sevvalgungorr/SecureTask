const KEY = "securetask_token";
const token = () => localStorage.getItem(KEY);
const RING_C = 2 * Math.PI * 36;

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.classList.add("show");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 2200);
}

// Every API call carries the bearer token. A 401 means the token expired —
// drop it and fall back to the login screen.
async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token(),
      ...(options.headers || {}),
    },
  });
  if (res.status === 401) { clearSession(); throw new Error("oturum süresi doldu"); }
  if (res.status === 429) { toast("Çok fazla istek — lütfen biraz yavaşla"); throw new Error("rate limited"); }
  if (!res.ok) {
    // Sunucunun gerekçesini taşı: bir 403 "yasak" demekle kalmamalı, neden
    // reddedildiğini de söylemeli (ör. adım-adım MFA gerekiyor).
    let detail = "";
    try { detail = (await res.json()).detail || ""; } catch (e) { /* gövde JSON değil */ }
    const err = new Error(detail || "istek başarısız (" + res.status + ")");
    err.status = res.status;
    throw err;
  }
  return res.status === 200 ? res.json() : null;
}

// Local sign-out: forget our token and fall back to the login screen. Used when
// a token simply expired — no reason to disturb the provider's SSO session.
function clearSession() { localStorage.removeItem(KEY); render(); }

// Full sign-out (the Çıkış button): also end the provider's SSO session, so the
// next login really asks for credentials instead of silently reusing the old one.
async function logout() {
  let url = null;
  try {
    // Plain fetch, not api(): api() calls clearSession() on a 401, and routing
    // sign-out through it would fight with the redirect we are about to make.
    const res = await fetch("/auth/logout");
    if (res.ok) url = (await res.json()).logout_url;
  } catch (e) { /* provider unreachable — the local sign-out below still stands */ }
  // Drop our token first, so a failed redirect can never leave the user signed in.
  localStorage.removeItem(KEY);
  if (url) location.href = url; else render();
}

const PENCIL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>';
const TRASH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m2 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>';
const CAL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>';
const SEV_LABEL = { low: "Düşük", medium: "Orta", high: "Yüksek", critical: "Kritik" };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const STATUS_LABEL = { open: "Açık", triaged: "Triyaj", fixed: "Düzeltildi", accepted_risk: "Risk kabul" };
// Both end the work; only one removes the problem.
const CLOSED = ["fixed", "accepted_risk"];
const isClosed = f => CLOSED.includes(f.status);

function fmtDate(d) { const p = d.split("-"); return p[2] + "." + p[1] + "." + p[0].slice(2); }
function today() { return new Date().toISOString().slice(0, 10); }
// An SLA is only breached while the finding is still open; a closed one cannot
// go on being late.
function isOverdue(f) { return f.due_date && !isClosed(f) && f.due_date < today(); }

function memberName(teamId, userId) {
  const team = teamById(teamId);
  const member = team && team.members.find(m => m.user_id === userId);
  return member ? member.username : "#" + userId;
}

function findingMeta(f) {
  const meta = document.createElement("div");
  meta.className = "meta";
  const sev = document.createElement("span");
  sev.className = "sev sev-" + f.severity;
  sev.textContent = SEV_LABEL[f.severity] || f.severity;
  meta.appendChild(sev);
  if (f.asset) {
    const asset = document.createElement("span");
    asset.className = "asset";
    asset.textContent = f.asset;          // textContent → XSS'e kapalı
    meta.appendChild(asset);
  }
  if (f.source && f.source !== "manual") {
    const src = document.createElement("span");
    src.className = "src";
    src.textContent = f.source;
    src.title = f.source_ref || "";
    meta.appendChild(src);
  }
  if (f.team_id) {
    const team = teamById(f.team_id);
    const chip = document.createElement("span");
    chip.className = "team-chip";
    chip.textContent = team ? team.name : "ekip";
    chip.title = "Bu bulguyu ekipteki herkes görür";
    meta.appendChild(chip);

    const who = document.createElement("span");
    who.className = "assignee" + (f.assignee_id ? "" : " none");
    who.textContent = f.assignee_id
      ? "atanan: " + memberName(f.team_id, f.assignee_id)
      : "atanmamış";
    meta.appendChild(who);
  }
  if (f.due_date) {
    const due = document.createElement("span");
    due.className = "due" + (isOverdue(f) ? " overdue" : "");
    const label = document.createElement("span");
    label.textContent = "SLA " + fmtDate(f.due_date) + (isOverdue(f) ? " · aşıldı" : "");
    due.innerHTML = CAL;                  // static icon markup only
    due.appendChild(label);
    meta.appendChild(due);
  }
  return meta;
}

const MAX_ACCEPTANCE_DAYS = 90;

function addDays(n) {
  const d = new Date(); d.setDate(d.getDate() + n);
  return d.toISOString().slice(0, 10);
}

// Riski kabul etmek için gerekçe ve bitiş tarihi ister. Sunucu zaten ikisini de
// zorunlu tutuyor; buradaki amaç kullanıcıyı hatayla karşılaştırmak değil,
// kararı verirken düşündürmek. Bir promise döner: {reason, until} ya da null.
function askAcceptance(f) {
  return new Promise(resolve => {
    const back = document.createElement("div");
    back.className = "modal-backdrop";

    const box = document.createElement("div");
    box.className = "modal";

    const h = document.createElement("h3");
    h.textContent = "Riski kabul et";
    const why = document.createElement("p");
    why.className = "why";
    why.textContent =
      "Bu bulgu açık kalacak. Neden bu riskle yaşadığınız ve ne zamana kadar " +
      "kabul edildiği kayda geçer; süre dolunca bulgu kendiliğinden yeniden açılır.";

    const err = document.createElement("p");
    err.className = "err";

    const f1 = document.createElement("div"); f1.className = "field";
    const l1 = document.createElement("label"); l1.textContent = "Gerekçe";
    const reason = document.createElement("textarea");
    reason.placeholder = "Ör: Sağlayıcı yaması çıkana kadar ağ tarafında sınırlandırıldı";
    f1.append(l1, reason);

    const f2 = document.createElement("div"); f2.className = "field";
    const l2 = document.createElement("label"); l2.textContent = "Bitiş tarihi";
    const until = document.createElement("input");
    until.type = "date";
    until.value = addDays(30);
    until.min = addDays(1);
    until.max = addDays(MAX_ACCEPTANCE_DAYS);
    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = `En fazla ${MAX_ACCEPTANCE_DAYS} gün. Sonsuza kadar kabul yoktur.`;
    f2.append(l2, until, hint);

    const row = document.createElement("div"); row.className = "row";
    const cancel = document.createElement("button");
    cancel.className = "btn ghost sm"; cancel.type = "button"; cancel.textContent = "Vazgeç";
    const ok = document.createElement("button");
    ok.className = "btn sm"; ok.type = "button"; ok.textContent = "Kabul et";
    row.append(cancel, ok);

    const close = value => { back.remove(); document.removeEventListener("keydown", onKey); resolve(value); };
    const onKey = e => { if (e.key === "Escape") close(null); };

    cancel.onclick = () => close(null);
    back.onclick = e => { if (e.target === back) close(null); };
    document.addEventListener("keydown", onKey);
    ok.onclick = () => {
      const text = reason.value.trim();
      if (text.length < 15) { err.textContent = "Gerekçe en az 15 karakter olmalı."; reason.focus(); return; }
      if (!until.value) { err.textContent = "Bir bitiş tarihi seç."; return; }
      close({ reason: text, until: until.value });
    };

    box.append(h, why, err, f1, f2, row);
    back.appendChild(box);
    document.body.appendChild(back);
    reason.focus();
  });
}

// The row's own status control. Changing it PUTs the finding, so the change
// lands in the audit log the same way any other edit does.
function stateSelect(f, after) {
  const sel = document.createElement("select");
  sel.className = "state-select";
  sel.title = "Durum";
  // Bu oturum MFA'dan geçmediyse risk kabulünün reddedileceğini önceden söyle;
  // kullanıcı denemeden önce bilsin. Seçenek yine de gizlenmiyor — sunucu tek
  // yetkili, arayüz yalnızca haber veriyor.
  const needsStepUp = currentUser && currentUser.step_up_required && !currentUser.mfa;
  // Görev ayrılığı, MFA'dan önce gelir: ikinci faktörü olan biri de kendi
  // bildirdiği bulgunun riskini kabul edemez.
  const blocked = acceptBlockedReason(f);
  Object.entries(STATUS_LABEL).forEach(([value, label]) => {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = value !== "accepted_risk"
      ? label
      : blocked ? label + " (" + blocked + ")"
      : needsStepUp ? label + " (MFA gerekir)"
      : label;
    if (value === "accepted_risk" && blocked) opt.disabled = true;
    if (f.status === value) opt.selected = true;
    sel.appendChild(opt);
  });
  sel.onchange = async () => {
    let extra = {};
    if (sel.value === "accepted_risk") {
      const answer = await askAcceptance(f);
      if (!answer) { after(); return; }        // vazgeçildi: seçim geri alınır
      extra = { accepted_reason: answer.reason, accepted_until: answer.until };
    }
    try {
      await saveFinding({ ...f, status: sel.value, ...extra });
      toast("Durum: " + STATUS_LABEL[sel.value]);
    } catch (e) {
      // Reddedilirse listeyi tazelemek seçimi eski durumuna geri alır.
      toast(e.message);
    }
    after();
  };
  return sel;
}

let myFindings = [];
let filter = "all";
let query = "";
let sevPick = "";
let srcPick = "";
let overdueOnly = false;
let currentUser = null;

// A closed finding is struck through, except when the risk was accepted: that
// one stays legible, because it is still a live risk someone chose to carry.
function rowClass(f) {
  if (f.status === "accepted_risk") return "finding accepted";
  return "finding" + (isClosed(f) ? " closed" : "");
}

// Atama kendi ucundan gider: bir başlık düzeltmesinin yan etkisi olarak birinin
// işi başkasına devredilmemeli.
function assigneeSelect(f) {
  const sel = document.createElement("select");
  sel.className = "assign-select";
  sel.title = "Kim ilgilenecek";
  const none = document.createElement("option");
  none.value = ""; none.textContent = "— atanmamış —";
  sel.appendChild(none);
  const team = teamById(f.team_id);
  (team ? team.members : []).forEach(m => {
    const o = document.createElement("option");
    o.value = String(m.user_id); o.textContent = m.username;
    if (f.assignee_id === m.user_id) o.selected = true;
    sel.appendChild(o);
  });
  sel.onchange = async () => {
    try {
      await api("/findings/" + f.id + "/assignee", {
        method: "PUT",
        body: JSON.stringify({ assignee_id: sel.value ? Number(sel.value) : null }),
      });
      toast(sel.value ? "Atandı: " + memberName(f.team_id, Number(sel.value)) : "Atama kaldırıldı");
    } catch (e) { toast(e.message); }
    loadFindings();
  };
  return sel;
}

function findingRow(f) {
  const li = document.createElement("li");
  li.className = rowClass(f);

  const body = document.createElement("div");
  body.className = "body";
  const wrap = document.createElement("div");
  wrap.className = "title-wrap";
  const title = document.createElement("div");
  title.className = "title"; title.textContent = f.title;
  wrap.appendChild(title);
  if (f.description) {
    const d = document.createElement("div");
    d.className = "desc"; d.textContent = f.description;
    wrap.appendChild(d);
  }
  body.appendChild(wrap);
  body.appendChild(findingMeta(f));
  if (f.status === "accepted_risk" && f.accepted_reason) {
    const note = document.createElement("div");
    note.className = "accepted-note";
    const label = document.createElement("b");
    label.textContent = "Risk kabul — " + fmtDate(f.accepted_until) + "'e kadar: ";
    note.appendChild(label);
    note.appendChild(document.createTextNode(f.accepted_reason));
    body.appendChild(note);
  }

  const actions = document.createElement("div");
  actions.className = "actions";
  if (f.team_id) actions.appendChild(assigneeSelect(f));
  const edit = document.createElement("button");
  edit.className = "icon-btn"; edit.title = "Düzenle";
  edit.innerHTML = PENCIL; edit.onclick = () => startEdit(li, f);
  const del = document.createElement("button");
  del.className = "icon-btn del-x"; del.title = "Sil";
  del.innerHTML = TRASH; del.onclick = () => remove(f);
  actions.append(edit, del);

  li.append(stateSelect(f, loadFindings), body, actions);
  return li;
}

// Every write goes through here, so the payload stays complete: a PUT replaces
// the whole finding, and a partial body would silently blank the other fields.
function saveFinding(f) {
  return api("/findings/" + f.id, {
    method: "PUT",
    body: JSON.stringify({
      title: f.title,
      description: f.description,
      asset: f.asset || "",
      severity: f.severity,
      status: f.status,
      due_date: f.due_date,
      // Ekip, güncelleme ile değiştirilemez; olduğu gibi geri gönderiliyor ki
      // sunucu "bu bir taşıma denemesi mi" sorusuna doğru cevabı bulsun.
      team_id: f.team_id ?? null,
      // Tam gövde gönderiliyor: eksik bırakmak kabulün gerekçesini ve süresini
      // sessizce silerdi.
      accepted_reason: f.accepted_reason || null,
      accepted_until: f.accepted_until || null,
    }),
  });
}

// Inline rename: swap the title for an input, save on Enter/blur, cancel on Esc.
function startEdit(li, f) {
  const titleEl = li.querySelector(".title");
  const input = document.createElement("input");
  input.className = "title-edit"; input.value = f.title;
  titleEl.replaceWith(input);
  input.focus(); input.select();
  let saving = false;
  const save = async () => {
    if (saving) return; saving = true;
    const v = input.value.trim();
    if (v && v !== f.title) {
      await saveFinding({ ...f, title: v });
      toast("Bulgu güncellendi");
    }
    loadFindings();
  };
  input.onkeydown = (e) => {
    if (e.key === "Enter") { e.preventDefault(); save(); }
    if (e.key === "Escape") { saving = true; loadFindings(); }
  };
  input.onblur = save;
}

function setStats(findings) {
  const total = findings.length, closed = findings.filter(isClosed).length;
  const pct = total ? Math.round(closed / total * 100) : 0;
  document.getElementById("stDone").textContent = closed;
  document.getElementById("stPend").textContent = total - closed;
  document.getElementById("ringPct").textContent = pct + "%";
  document.getElementById("ringFg").style.strokeDashoffset = RING_C * (1 - pct / 100);
}

// Aranan metin başlıkta, varlıkta, açıklamada ve kuralın kimliğinde aranır —
// bir analistin elinde genelde bunlardan biri olur: "hangi dosyaydı", "şu CVE",
// "portal olan hangisiydi".
function matchesQuery(f) {
  if (!query) return true;
  return [f.title, f.asset, f.description, f.source_ref, f.source]
    .some(v => (v || "").toLowerCase().includes(query));
}

function renderMyList() {
  const shown = myFindings
    .filter(f => filter === "all" ? true : filter === "open" ? !isClosed(f) : isClosed(f))
    .filter(f => !sevPick || f.severity === sevPick)
    .filter(f => !srcPick || (f.source || "manual") === srcPick)
    .filter(f => !overdueOnly || isOverdue(f))
    .filter(matchesQuery)
    .sort((a, b) => {
      if (isClosed(a) !== isClosed(b)) return isClosed(a) ? 1 : -1;       // açık olanlar üstte
      if (a.severity !== b.severity) return SEV_ORDER[a.severity] - SEV_ORDER[b.severity];
      if (a.due_date && b.due_date) return a.due_date < b.due_date ? -1 : 1;
      if (a.due_date) return -1;
      if (b.due_date) return 1;
      return a.id - b.id;
    });
  const list = document.getElementById("findingList");
  document.getElementById("emptyState").classList.toggle("hidden", myFindings.length > 0);
  list.innerHTML = "";
  shown.forEach(f => list.appendChild(findingRow(f)));

  // Süzme sonucu boş çıkabilir; bunu "hiç bulgun yok" ile karıştırmamak için
  // sayaç her zaman kaç kaydın kaç kayıttan süzüldüğünü söyler.
  const count = document.getElementById("matchCount");
  count.textContent = shown.length === myFindings.length
    ? `${myFindings.length} bulgu`
    : `${shown.length} / ${myFindings.length} bulgu`;
}

// Kaynak listesi veriden türetilir: elde yalnızca nuclei varsa menüde yalnızca
// nuclei görünür — hiç kullanılmamış bir seçenek sunmanın anlamı yok.
function refreshSourceOptions() {
  const select = document.getElementById("srcFilter");
  const sources = [...new Set(myFindings.map(f => f.source || "manual"))].sort();
  const current = select.value;
  select.innerHTML = "";
  const all = document.createElement("option");
  all.value = ""; all.textContent = "Kaynak: hepsi";
  select.appendChild(all);
  sources.forEach(s => {
    const o = document.createElement("option");
    o.value = s; o.textContent = s;
    select.appendChild(o);
  });
  select.value = sources.includes(current) ? current : "";
  srcPick = select.value;
}

async function loadFindings() {
  myFindings = await api("/findings");
  setStats(myFindings);
  refreshSourceOptions();
  renderMyList();
}

function setupFilters() {
  document.querySelectorAll("#filters .chip").forEach(c => {
    c.onclick = () => {
      document.querySelectorAll("#filters .chip").forEach(x => x.classList.remove("active"));
      c.classList.add("active");
      filter = c.dataset.f;
      renderMyList();
    };
  });
}
setupFilters();

function setupFilterBar() {
  const search = document.getElementById("searchInput");
  search.oninput = () => { query = search.value.trim().toLowerCase(); renderMyList(); };
  document.getElementById("sevFilter").onchange = e => { sevPick = e.target.value; renderMyList(); };
  document.getElementById("srcFilter").onchange = e => { srcPick = e.target.value; renderMyList(); };
  document.getElementById("overdueOnly").onchange = e => { overdueOnly = e.target.checked; renderMyList(); };
}
setupFilterBar();

async function remove(f) {
  await api("/findings/" + f.id, { method: "DELETE" });
  toast("Bulgu silindi"); loadFindings();
}

document.getElementById("addForm").onsubmit = async (e) => {
  e.preventDefault();
  const title = document.getElementById("titleInput");
  const asset = document.getElementById("assetInput");
  const desc = document.getElementById("descInput");
  const sev = document.getElementById("sevInput");
  const due = document.getElementById("dueInput");
  const team = document.getElementById("teamInput");
  if (!title.value.trim()) return;
  // due_date left empty on purpose: the server fills it from the severity SLA.
  await api("/findings", {
    method: "POST",
    body: JSON.stringify({
      title: title.value.trim(),
      description: desc.value.trim() || null,
      asset: asset.value.trim(),
      severity: sev.value,
      due_date: due.value || null,
      team_id: team.value ? Number(team.value) : null,
    }),
  });
  title.value = ""; asset.value = ""; desc.value = ""; sev.value = "medium"; due.value = "";
  toast("Bulgu kaydedildi"); loadFindings();
};

// Tarama çıktısını içe aktar. Dosya tarayıcıda okunur ve gövdesi olduğu gibi
// gönderilir — ayrıştırma sunucuda yapılır, çünkü kuralları (tekilleştirme,
// yeniden açma, risk kabulüne dokunmama) uygulayan taraf orası.
document.getElementById("importInput").onchange = async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const label = document.getElementById("importLabel");
  const note = document.getElementById("importNote");
  label.textContent = "Yükleniyor…";
  note.textContent = "";
  try {
    // Taramanın nereye düşeceğini de yukarıdaki ekip seçimi belirler: sonuç,
    // tarayıcıyı çalıştıran kişinin değil, işi yapacak ekibin olmalı.
    const team = document.getElementById("teamInput").value;
    const body = await file.text();
    // Hangi uca gideceğini dosyanın kendisi söylüyor: SARIF bir JSON nesnesidir
    // ve "runs" dizisi taşır; nuclei ise şablon kimliği olan kayıtlar üretir.
    // Kullanıcıya "bu hangi format" diye sormak, cevabı dosyada yazarken
    // gereksiz bir soru olurdu.
    const endpoint = /"runs"\s*:/.test(body.slice(0, 4000)) ? "sarif" : "nuclei";
    const path = "/import/" + endpoint + (team ? "?team_id=" + team : "");
    const r = await api(path, { method: "POST", body });
    note.textContent =
      `${r.tool}: ${r.created} yeni · ${r.reopened} yeniden açıldı · ${r.unchanged} değişmedi` +
      (r.kept_accepted ? ` · ${r.kept_accepted} risk kabul korundu` : "") +
      (r.skipped ? ` · ${r.skipped} okunamadı` : "");
    toast(`${r.created} bulgu içe aktarıldı (${r.tool})`);
    loadFindings();
  } catch (err) {
    note.textContent = err.message;
  } finally {
    label.textContent = "Dosya seç…";
    e.target.value = "";     // aynı dosya tekrar seçilebilsin
  }
};

document.getElementById("expireBtn").onclick = async (e) => {
  const btn = e.target; btn.disabled = true;
  try {
    const r = await api("/risk/expire", { method: "POST" });
    toast(r.reopened
      ? `${r.reopened} risk kabulünün süresi doldu, bulgu yeniden açıldı`
      : "Süresi dolmuş risk kabulü yok");
    loadFindings();
  } catch (err) { toast(err.message); } finally { btn.disabled = false; }
};

document.getElementById("verifyBtn").onclick = async (e) => {
  const btn = e.target; btn.disabled = true;
  const out = document.getElementById("chainResult");
  try {
    const r = await api("/admin/audit/verify");
    out.innerHTML = "";
    const mark = document.createElement("span");
    mark.className = r.ok ? "ok" : "bad";
    mark.textContent = r.ok ? "✓ Zincir sağlam" : "✗ Zincir kırık";
    const detail = document.createElement("span");
    detail.textContent = r.ok
      ? `${r.checked} kayıt doğrulandı, hiçbiri değiştirilmemiş.`
      : `#${r.broken_at} numaralı kayıtta: ${r.reason}`;
    out.append(mark, detail);
  } catch (err) { toast(err.message); } finally { btn.disabled = false; }
};

// --- Ekipler ---------------------------------------------------------------
//
// Ekip, bu uygulamadaki kontrollerin anlam kazandığı yer: ikinci faktör de,
// yazılı gerekçe de, zincirli günlük de birini kısıtlar. Listeyi tek başına
// tutan biri için kısıtlanacak kimse yoktur.

let myTeams = [];
const teamById = id => myTeams.find(t => t.id === id) || null;
const ROLE_LABEL = { member: "üye", risk_owner: "risk sahibi" };

// Ekipteki kişinin bu bulguyu kabul edip edemeyeceği. Sunucu tek yetkili karar
// mercii; buradaki amaç kullanıcıyı reddedilecek bir işe sokmamak.
function acceptBlockedReason(f) {
  if (!f.team_id) return null;
  const team = teamById(f.team_id);
  if (team && team.my_role !== "risk_owner") return "risk sahibi gerekir";
  if (currentUser && f.owner_id === currentUser.id) return "kendi bildirdiğin bulgu";
  return null;
}

function memberChip(team, m) {
  const chip = document.createElement("span");
  chip.className = "member" + (m.role === "risk_owner" ? " owner" : "");
  const name = document.createElement("b");
  name.textContent = m.username;
  const role = document.createElement("small");
  role.textContent = ROLE_LABEL[m.role] || m.role;
  chip.append(name, role);

  if (team.my_role === "risk_owner" && !(currentUser && m.user_id === currentUser.id)) {
    const x = document.createElement("button");
    x.className = "icon-btn del-x"; x.title = "Ekipten çıkar";
    x.innerHTML = TRASH;
    x.onclick = async () => {
      try {
        await api(`/teams/${team.id}/members/${m.user_id}`, { method: "DELETE" });
        toast(m.username + " ekipten çıkarıldı");
        loadTeams();
      } catch (e) { toast(e.message); }
    };
    chip.appendChild(x);
  }
  return chip;
}

function teamCard(team) {
  const card = document.createElement("div");
  card.className = "team-card";

  const head = document.createElement("div");
  head.className = "team-head";
  const name = document.createElement("b");
  name.textContent = team.name;                     // textContent → XSS'e kapalı
  const mine = document.createElement("span");
  mine.className = "badge";
  mine.textContent = ROLE_LABEL[team.my_role] || team.my_role;
  head.append(name, mine);

  const members = document.createElement("div");
  members.className = "members";
  team.members.forEach(m => members.appendChild(memberChip(team, m)));

  card.append(head, members);

  if (team.my_role === "risk_owner") {
    const form = document.createElement("form");
    form.className = "add-member";
    const email = document.createElement("input");
    email.type = "email"; email.placeholder = "E-posta ile ekle"; email.required = true;
    const role = document.createElement("select");
    role.className = "mini-select";
    [["member", "üye"], ["risk_owner", "risk sahibi"]].forEach(([v, l]) => {
      const o = document.createElement("option"); o.value = v; o.textContent = l;
      role.appendChild(o);
    });
    const add = document.createElement("button");
    add.className = "btn ghost sm"; add.type = "submit"; add.textContent = "Ekle";
    form.append(email, role, add);
    form.onsubmit = async e => {
      e.preventDefault();
      try {
        await api(`/teams/${team.id}/members`, {
          method: "POST",
          body: JSON.stringify({ email: email.value.trim(), role: role.value }),
        });
        email.value = "";
        toast("Üye eklendi");
        loadTeams();
      } catch (err) { toast(err.message); }
    };
    card.appendChild(form);
  }

  return card;
}

function fillTeamSelect() {
  const sel = document.getElementById("teamInput");
  const chosen = sel.value;
  sel.innerHTML = "";
  const personal = document.createElement("option");
  personal.value = ""; personal.textContent = "Kişisel";
  sel.appendChild(personal);
  myTeams.forEach(t => {
    const o = document.createElement("option");
    o.value = String(t.id); o.textContent = t.name;
    sel.appendChild(o);
  });
  sel.value = chosen && myTeams.some(t => String(t.id) === chosen) ? chosen : "";
}

function renderTeams() {
  const host = document.getElementById("teamList");
  host.innerHTML = "";
  document.getElementById("teamsEmpty").classList.toggle("hidden", myTeams.length > 0);
  myTeams.forEach(t => host.appendChild(teamCard(t)));
}

async function loadTeams() {
  myTeams = await api("/teams");
  fillTeamSelect();
  renderTeams();
}

document.getElementById("teamForm").onsubmit = async e => {
  e.preventDefault();
  const input = document.getElementById("teamName");
  if (!input.value.trim()) return;
  try {
    await api("/teams", { method: "POST", body: JSON.stringify({ name: input.value.trim() }) });
    input.value = "";
    toast("Ekip kuruldu — risk sahibi sensin");
    loadTeams();
  } catch (err) { toast(err.message); }
};

// --- İzlenen varlıklar -----------------------------------------------------

function assetRow(a) {
  const li = document.createElement("li");
  li.className = "finding";

  const body = document.createElement("div");
  body.className = "body";
  const title = document.createElement("div");
  title.className = "title";
  title.textContent = a.host;                  // textContent → XSS'e kapalı
  body.appendChild(title);
  if (a.label) {
    const d = document.createElement("div");
    d.className = "desc"; d.textContent = a.label;
    body.appendChild(d);
  }

  const del = document.createElement("button");
  del.className = "icon-btn del-x"; del.title = "Kaldır";
  del.innerHTML = TRASH;
  del.onclick = async () => {
    await api("/assets/" + a.id, { method: "DELETE" });
    toast("Varlık kaldırıldı"); loadAssets();
  };

  li.append(body, del);
  return li;
}

async function loadAssets() {
  const assets = await api("/assets");
  const list = document.getElementById("assetList");
  document.getElementById("assetsEmpty").classList.toggle("hidden", assets.length > 0);
  list.innerHTML = "";
  assets.forEach(a => list.appendChild(assetRow(a)));
}

document.getElementById("assetForm").onsubmit = async (e) => {
  e.preventDefault();
  const host = document.getElementById("assetHost");
  const label = document.getElementById("assetLabel");
  if (!host.value.trim()) return;
  try {
    await api("/assets", {
      method: "POST",
      body: JSON.stringify({ host: host.value.trim(), label: label.value.trim() }),
    });
    host.value = ""; label.value = "";
    toast("Varlık eklendi"); loadAssets();
  } catch (err) {
    // Reddedilen bir hedefin sebebi (özel adrese çözümleniyor, zaten kayıtlı)
    // kullanıcıya aynen gösterilir — sessizce başarısız olmaz.
    toast(err.message);
  }
};

document.getElementById("runMonitorBtn").onclick = async (e) => {
  const btn = e.target;
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = "Çalışıyor…";
  try {
    const r = await api("/monitor/run", { method: "POST" });
    const parts = [
      `${r.checked} varlık kontrol edildi`,
      r.created ? `${r.created} yeni bulgu` : "",
      r.escalated ? `${r.escalated} yükseltildi` : "",
      r.reopened ? `${r.reopened} yeniden açıldı` : "",
      r.resolved ? `${r.resolved} kapandı` : "",
    ].filter(Boolean);
    document.getElementById("monitorNote").textContent =
      parts.join(" · ") +
      (r.refused.length ? ` · ${r.refused.length} hedef reddedildi: ` +
        r.refused.map(x => x.host).join(", ") : "");
    toast(parts.join(" · "));
    loadFindings();
  } catch (err) {
    toast(err.message);
  } finally {
    btn.disabled = false; btn.textContent = label;
  }
};

// --- Admin panel ---------------------------------------------------------

function adminFindingRow(f) {
  const li = document.createElement("li");
  li.className = rowClass(f);

  const state = document.createElement("span");
  // The admin list is read-only on state: an admin browsing everyone's findings
  // should not be able to change someone else's risk decision by mis-clicking.
  state.className = "act " + (f.status === "fixed" ? "created" : isClosed(f) ? "deleted" : "updated");
  state.textContent = STATUS_LABEL[f.status] || f.status;

  const body = document.createElement("div");
  body.className = "body";
  const wrap = document.createElement("div");
  wrap.className = "title-wrap";
  const title = document.createElement("div");
  title.className = "title"; title.textContent = f.title;
  wrap.appendChild(title);
  if (f.description) {
    const d = document.createElement("div");
    d.className = "desc"; d.textContent = f.description;
    wrap.appendChild(d);
  }
  body.appendChild(wrap);
  body.appendChild(findingMeta(f));

  const owner = document.createElement("span");
  owner.className = "owner-badge"; owner.textContent = "sahip #" + f.owner_id;

  const del = document.createElement("button");
  del.className = "icon-btn del-x"; del.title = "Sil (admin)";
  del.innerHTML = TRASH;
  del.onclick = async () => {
    if (!confirm("Bu bulguyu silmek istediğine emin misin?")) return;
    await api("/admin/findings/" + f.id, { method: "DELETE" });
    toast("Bulgu silindi (admin)"); loadAdmin();
  };

  li.append(state, body, owner, del);
  return li;
}

function auditRow(a) {
  const li = document.createElement("li");
  li.className = "audit-row";
  const act = document.createElement("span");
  act.className = "act " + a.action;
  act.textContent = {
    created: "eklendi", updated: "güncellendi", deleted: "silindi",
    imported: "içe aktarıldı", monitored: "izlendi", expired: "süresi doldu",
    access_denied: "reddedildi",
  }[a.action] || a.action;
  const what = document.createElement("span");
  what.className = "what";
  // İçe aktarma kaydı tek bir bulguya ait değil, o yüzden id'si yok.
  const ref = a.finding_id ? "#" + a.finding_id : "";
  what.textContent = [ref, a.detail].filter(Boolean).join(" · ");
  const when = document.createElement("span");
  when.className = "when";
  when.textContent = a.created_at ? a.created_at.slice(11, 19) : "";
  li.append(act, what, when);
  return li;
}

async function loadAdmin() {
  const all = await api("/admin/findings");
  document.getElementById("allCount").textContent = all.length;
  const at = document.getElementById("allFindings");
  at.innerHTML = "";
  all.forEach(f => at.appendChild(adminFindingRow(f)));

  const log = await api("/admin/audit");
  const al = document.getElementById("auditList");
  al.innerHTML = "";
  log.forEach(a => al.appendChild(auditRow(a)));
}

/* ── Pano ──────────────────────────────────────────────────────────────────
   Grafikler saf SVG ile çizilir. Bunun sebebi yalnızca sadelik değil: kendi
   eklediğimiz Content-Security-Policy başlığı dışarıdan script yüklemeyi
   engelliyor, yani bir grafik kütüphanesi zaten yüklenemezdi. */

const SVG_NS = "http://www.w3.org/2000/svg";

// Yerel (UTC değil) gün anahtarı: UTC'ye çevirmek olayları bir gün kaydırabilir.
const dayKey = d =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;

function lastDays(n) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return Array.from({ length: n }, (_, i) => {
    const d = new Date(today);
    d.setDate(today.getDate() - (n - 1 - i));
    return d;
  });
}

function svgEl(name, attrs = {}) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

// Tek serilik sütun grafiği: iş "zaman içindeki büyüklük", o yüzden tek renk —
// ayrı renkler kimlik ima ederdi, burada ayırt edilecek bir kimlik yok.
function columnChart(host, points, opts = {}) {
  const W = 560, H = 148, PAD_B = 20, PAD_T = 8;
  const plotH = H - PAD_B - PAD_T;
  const max = Math.max(1, ...points.map(p => p.value));
  const slot = W / points.length;
  const bw = Math.min(24, slot * 0.6);

  const svg = svgEl("svg", {
    viewBox: `0 0 ${W} ${H}`, role: "img",
    "aria-label": opts.aria || "",
  });
  svg.appendChild(svgEl("line", { x1: 0, x2: W, y1: H - PAD_B, y2: H - PAD_B, class: "axis" }));

  points.forEach((p, i) => {
    // Sıfır yükseklikli bir çubuğun üzerine gelinemez; şeffaf ve tam boy bir
    // isabet alanı, imleç hedefini işaretten büyük tutar.
    const hit = svgEl("rect", {
      x: i * slot, y: PAD_T, width: slot, height: plotH, class: "hit",
    });
    const title = svgEl("title");
    title.textContent = p.label;
    hit.appendChild(title);
    hit.addEventListener("mouseenter", () => showTip(host, i * slot + slot / 2, W, p.label));
    hit.addEventListener("mouseleave", () => hideTip(host));
    svg.appendChild(hit);

    const h = p.value === 0 ? 0 : Math.max(3, (p.value / max) * plotH);
    svg.appendChild(svgEl("rect", {
      x: i * slot + (slot - bw) / 2, y: H - PAD_B - h,
      width: bw, height: h, rx: 4,
      class: "bar" + (opts.tone ? " " + opts.tone : ""),
    }));

    if (p.tick) {
      const t = svgEl("text", {
        x: i * slot + slot / 2, y: H - PAD_B + 14,
        "text-anchor": "middle", class: "tick",
      });
      t.textContent = p.tick;
      svg.appendChild(t);
    }
  });

  host.innerHTML = "";
  host.appendChild(svg);
  const tip = document.createElement("div");
  tip.className = "chart-tip";
  host.appendChild(tip);
}

function showTip(host, xInViewBox, viewBoxW, text) {
  const tip = host.querySelector(".chart-tip");
  if (!tip) return;
  tip.textContent = text;
  tip.style.left = (xInViewBox / viewBoxW) * host.clientWidth + "px";
  tip.style.top = "0px";
  tip.classList.add("show");
}

function hideTip(host) {
  const tip = host.querySelector(".chart-tip");
  if (tip) tip.classList.remove("show");
}

function dailyCounts(entries, days) {
  const counts = new Map(days.map(d => [dayKey(d), 0]));
  entries.forEach(e => {
    const k = dayKey(new Date(e.created_at));
    if (counts.has(k)) counts.set(k, counts.get(k) + 1);
  });
  return days.map((d, i) => ({
    value: counts.get(dayKey(d)),
    label: `${d.toLocaleDateString("tr-TR", { day: "numeric", month: "long" })} — ${counts.get(dayKey(d))} işlem`,
    // Her sütuna etiket koymak okunmaz olurdu; iki günde bir yeter.
    tick: i % 2 === 0 ? d.getDate() : "",
  }));
}

// Yalnızca AÇIK bulguların dağılımı: kapatılmışları da saymak, taşınan riski
// olduğundan küçük gösterirdi — asıl soru "şu an neyi taşıyoruz".
function renderSeverity(findings) {
  const order = [
    { key: "critical", cls: "s4", label: "Kritik" },
    { key: "high", cls: "s3", label: "Yüksek" },
    { key: "medium", cls: "s2", label: "Orta" },
    { key: "low", cls: "s1", label: "Düşük" },
  ];
  const total = findings.length;
  const stack = document.getElementById("sevStack");
  const legend = document.getElementById("sevLegend");
  stack.innerHTML = "";
  legend.innerHTML = "";

  order.forEach(o => {
    const n = findings.filter(f => (f.severity || "medium") === o.key).length;
    const seg = document.createElement("span");
    seg.className = o.cls;
    seg.style.flex = total ? n : 0;
    // Doğrudan etiket, ancak sığdığında: dar bir dilimde rakam okunmaz.
    seg.textContent = total && n / total > 0.12 ? n : "";
    seg.title = `${o.label}: ${n}`;
    stack.appendChild(seg);

    const item = document.createElement("span");
    const swatch = document.createElement("i");
    // Kimlik rengi işarette durur; sayı ve etiket metin renginde kalır.
    swatch.style.background = `var(--sev-${o.cls.slice(1)})`;
    item.appendChild(swatch);
    item.appendChild(document.createTextNode(o.label + " "));
    const b = document.createElement("b");
    b.textContent = n;
    item.appendChild(b);
    legend.appendChild(item);
  });
}

async function loadDash() {
  const findings = myFindings;
  const open = findings.filter(f => !isClosed(f));
  const closed = findings.length - open.length;
  const total = findings.length;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const overdue = open.filter(f => f.due_date && new Date(f.due_date) < today).length;
  const critical = open.filter(f => f.severity === "critical").length;

  document.getElementById("kTotal").textContent = open.length;
  document.getElementById("kTotalSub").textContent = total
    ? `${critical} kritik · toplam ${total} bulgu`
    : "henüz bulgu yok";
  document.getElementById("kRate").textContent = (total ? Math.round((closed / total) * 100) : 0) + "%";
  document.getElementById("kRateSub").textContent = total ? `${closed}/${total} kapatıldı` : "—";
  document.getElementById("kOverdue").textContent = overdue;
  document.getElementById("kOverdueCard").classList.toggle("alert", overdue > 0);

  renderSeverity(open);

  const days = lastDays(14);
  const log = await api("/audit/me");
  const points = dailyCounts(log, days);
  columnChart(document.getElementById("actChart"), points, {
    aria: "Son 14 günün günlük işlem sayısı",
  });

  // Panodaki son işlemler, geçmiş sekmesindeki listenin kısaltılmışı — aynı
  // satır bileşeni kullanılıyor ki iki yerde iki farklı görünüm oluşmasın.
  const recent = document.getElementById("recentAudit");
  recent.innerHTML = "";
  log.slice(0, 8).forEach(a => recent.appendChild(auditRow(a)));

  const week = points.slice(-7).reduce((s, p) => s + p.value, 0);
  document.getElementById("kWeek").textContent = week;
  const busiest = points.reduce((a, b) => (b.value > a.value ? b : a), points[0]);
  document.getElementById("actNote").textContent = busiest && busiest.value
    ? `En yoğun gün: ${busiest.label}.`
    : "Bu dönemde kayıtlı işlem yok.";

  // Reddedilen erişimler sistem geneli bir veri ve kullanıcıya bağlanmadan
  // yazılıyor, o yüzden yalnızca /admin/audit üzerinden ve yalnızca yöneticiye.
  const isAdmin = (currentUser?.roles || []).includes("admin");
  document.getElementById("denyBlock").classList.toggle("hidden", !isAdmin);
  if (isAdmin) {
    const all = await api("/admin/audit");
    const denied = all.filter(a => a.action === "access_denied");
    columnChart(document.getElementById("denyChart"), dailyCounts(denied, days), {
      tone: "danger",
      aria: "Son 14 günde reddedilen erişim denemeleri",
    });
  }
}

async function loadHistory() {
  const log = await api("/audit/me");
  const el = document.getElementById("myAuditList");
  document.getElementById("historyEmpty").classList.toggle("hidden", log.length > 0);
  el.innerHTML = "";
  log.forEach(a => el.appendChild(auditRow(a)));
}

// Bir JWT'nin gövdesini (base64url) çözüp claim'lerini okur — sadece GÖSTERMEK
// için, salt-okunur. İmza sunucuda doğrulanır; burada asla doğrulama yapılmaz.
function decodeJWT(t) {
  try {
    let p = t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    while (p.length % 4) p += "=";
    const json = decodeURIComponent(
      atob(p).split("").map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)).join("")
    );
    return JSON.parse(json);
  } catch { return {}; }
}

function fmtExpiry(exp) {
  if (!exp) return "—";
  const mins = Math.round((exp - Date.now() / 1000) / 60);
  const when = new Date(exp * 1000).toLocaleString("tr-TR");
  return mins > 0 ? `${when} (~${mins} dk kaldı)` : `${when} (süresi doldu)`;
}

async function loadSecurity() {
  const me = await api("/auth/me");
  const claims = decodeJWT(token());

  // Kimlik
  document.getElementById("secAvatar").textContent =
    (me.username || "?").trim().charAt(0).toUpperCase();
  document.getElementById("secName").textContent = me.username || "—";
  document.getElementById("secMail").textContent = me.email || claims.email || "—";
  const roles = (me.roles && me.roles.length) ? me.roles : ["kullanıcı"];
  const rc = document.getElementById("secRoles");
  rc.innerHTML = "";
  roles.forEach(r => {
    const s = document.createElement("span");
    s.className = "role-badge";
    s.textContent = r;                 // textContent → XSS'e kapalı
    rc.appendChild(s);
  });

  // Oturum & Token (claim'lerden)
  const kv = document.getElementById("secToken");
  kv.innerHTML = "";
  // amr/acr sunucudan gelir — token'ı burada çözmek yalnızca gösterim içindir,
  // yetki kararı her zaman sunucuda verilir.
  const amr = (me.amr || []).join(", ");
  [
    ["Sağlayıcı", claims.iss || "—"],
    ["Kimlik (sub)", claims.sub || "—"],
    ["Token geçerlilik", fmtExpiry(claims.exp)],
    ["Doğrulama yöntemi", amr || "sağlayıcı bildirmedi"],
    ["Bu oturum", me.mfa ? "MFA ile doğrulandı ✓" : "yalnızca parola — risk kabulü yapılamaz"],
  ].forEach(([k, v]) => {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v;
    kv.append(dt, dd);
  });
}

const VIEWS = { dash: "dashView", my: "myView", assets: "assetsView", teams: "teamsView", history: "historyView", security: "securityView", admin: "adminView" };
function setupTabs() {
  document.querySelectorAll(".tab").forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const v = btn.dataset.view;
      Object.values(VIEWS).forEach(id => document.getElementById(id).classList.add("hidden"));
      document.getElementById(VIEWS[v]).classList.remove("hidden");
      // Pano bulgu listesinden beslenir: sekmeye her dönüşte ikisi de tazelenir.
      if (v === "dash") loadFindings().then(loadDash).catch(() => {});
      if (v === "admin") loadAdmin().catch(() => {});
      if (v === "assets") loadAssets().catch(() => {});
      if (v === "teams") loadTeams().catch(() => {});
      if (v === "history") loadHistory().catch(() => {});
      if (v === "security") loadSecurity().catch(() => {});
    };
  });
}
setupTabs();

async function render() {
  const loginView = document.getElementById("loginView");
  const appView = document.getElementById("appView");
  const who = document.getElementById("who");

  if (!token()) {
    loginView.classList.remove("hidden");
    appView.classList.add("hidden");
    who.innerHTML = "";
    return;
  }

  loginView.classList.add("hidden");
  appView.classList.remove("hidden");

  // Draw the header before /auth/me is awaited. If that call fails with anything
  // other than a 401 (server down, database down) the user must still have a
  // Çıkış button to leave with, instead of being stranded in a blank session.
  // Static structure only — no user data in innerHTML.
  who.innerHTML =
    '<div class="avatar"></div>' +
    '<span class="name"></span>' +
    '<span class="role-badge hidden">admin</span>' +
    '<button class="btn ghost sm" id="logoutBtn">Çıkış</button>';
  document.getElementById("logoutBtn").onclick = logout;

  try {
    const me = await api("/auth/me");
    currentUser = me;
    const initial = (me.username || "?").trim().charAt(0).toUpperCase();
    const isAdmin = (me.roles || []).includes("admin");
    // User-controlled values go in via textContent, which renders them as
    // plain text and never executes HTML (prevents stored XSS via username).
    who.querySelector(".avatar").textContent = initial;
    who.querySelector(".name").textContent = me.username;
    who.querySelector(".role-badge").classList.toggle("hidden", !isAdmin);
    document.getElementById("hello").textContent = "Merhaba, " + (me.username || "") + " 👋";
    // Everyone gets Bulgularım + Geçmişim; the Yönetim tab is admin-only.
    document.getElementById("tabs").classList.remove("hidden");
    document.getElementById("adminTab").classList.toggle("hidden", !isAdmin);
    // Before the findings: a row cannot say which team it belongs to, or who
    // may accept its risk, until we know which teams this person is in.
    await loadTeams();
    await loadFindings();
    await loadDash();
  } catch (e) {
    // A 401 already signed us out inside api(); anything else leaves us signed
    // in but unable to load the profile, which the user deserves to be told.
    if (token()) toast("Profil yüklenemedi — sunucuya ulaşılamıyor");
  }
}

render();
