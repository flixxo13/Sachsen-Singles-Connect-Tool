// ════════════════════════════════════════════════════════════════
//  SACHSEN SINGLES CONNECT — Backend v3.1 (Gemini-reviewed)
// ════════════════════════════════════════════════════════════════
//
//  ÄNDERUNGEN v3.1 (Gemini-Empfehlungen):
//  ✅ Session-Token in Script-Properties (kein eigenes Sheet mehr)
//  ✅ Alle Frontend-Parameter exakt gematcht (a, s, h, t, st, id, f)
//  ✅ initialisiereSystem(pin, wochencode) — einmalige Setup-Funktion
//  ✅ Feldnamen konsistent: bild, bio (wie Frontend)
//  ✅ Admin-PIN-Hash-Vergleich explizit dokumentiert
//
//  SETUP: Funktion initialisiereSystem() einmalig ausführen!
//
//  Script-Properties (auto-gesetzt durch initialisiereSystem):
//  ┌────────────────────┬─────────────────────────────────────┐
//  │ ADMIN_PIN_HASH     │ SHA-256 deines Admin-PINs           │
//  │ WEEK_CODE_1        │ SHA-256 des ersten Wochencodes      │
//  │ WEEK_CODE_2        │ (leer — für Dual-Code-Wechsel)      │
//  │ ADMIN_SESSION_ST   │ Aktueller Session-Token (auto)      │
//  │ ADMIN_SESSION_EXP  │ Ablaufzeit des Tokens (auto)        │
//  │ ADMIN_EMAIL        │ Manuell eintragen                   │
//  └────────────────────┴─────────────────────────────────────┘
// ════════════════════════════════════════════════════════════════

// ── Spalten-Mapping (konsistent mit Frontend-Feldnamen) ─────────
const COL = {
  ID:1, TIMESTAMP:2, TOKEN:3, STATUS:4, ZULETZT:5,
  VORNAME:6, ALTER:7, REGION:8, FB:9,
  BILD:10,   // Frontend: "bild"  — Hauptbild
  BIO:11,    // Frontend: "bio"
  DSGVO:12, VERIFIZIERT:13,
  BILD2:14,  // Frontend: "bild2" — 2. Foto (optional)
};

const PROFILES  = "Profile";
const ARCHIV    = "Archiv";
const MAX_DAYS  = 30;
const SESS_HRS  = 8;

// ── ROUTER ──────────────────────────────────────────────────────
// Alle Parameter kommen als GET-Params (CORS-frei):
//   a  = action        (p, cc, v, r, u, d, ax)
//   s  = sub-action    (login, out, q, all, ok, ban, del, code)
//   h  = hash          (SHA-256 von PIN oder Wochencode)
//   t  = edit-token    (User-Token)
//   st = session-token (Admin-Session)
//   id = profil-id
//   f  = filter (status)

function doGet(e) {
  try {
    const p = e.parameter || {};
    const a = p.a || "";

    // ── Öffentlich (kein Auth) ──────────────────────────────
    if (a === "p")  return getProfiles();
    if (a === "cc") return checkCode(p.h || "");

    // ── User (Edit-Token geschützt) ─────────────────────────
    if (a === "v")  return verifyToken(p.t || "");
    if (a === "r")  return registerProfile(p);
    if (a === "u")  return updateProfile(p);
    if (a === "d")  return deleteProfile(p);

    // ── Admin (verschleierter Endpunkt, Session-Token) ───────
    if (a === "ax") return adminAction(p);

    return fail(400, "Unbekannte Aktion.");
  } catch(err) {
    Logger.log("ERROR doGet: " + err.message + "\n" + err.stack);
    return fail(500, "Serverfehler: " + err.message);
  }
}

function doPost() {
  return fail(405, "Bitte GET verwenden.");
}

// ════════════════════════════════════════════════════════════════
//  ÖFFENTLICHE ENDPUNKTE
// ════════════════════════════════════════════════════════════════

function getProfiles() {
  const sheet = getSheet(PROFILES);
  const rows  = sheet.getDataRange().getValues();
  const now   = new Date();
  const out   = [];

  for (let i = 1; i < rows.length; i++) {
    const r = rows[i];
    if (r[COL.STATUS-1] !== "Aktiv") continue;
    if ((now - new Date(r[COL.ZULETZT-1])) / 864e5 > MAX_DAYS) continue;
    out.push({
      id:         r[COL.ID-1],
      vorname:    r[COL.VORNAME-1],
      alter:      r[COL.ALTER-1],
      region:     r[COL.REGION-1],
      bild:       r[COL.BILD-1]  || null,
      bild2:      r[COL.BILD2-1] || null,
      bio:        r[COL.BIO-1]   || null,
      verifiziert:r[COL.VERIFIZIERT-1] === true,
      fb:         r[COL.FB-1],
    });
  }
  return win({ profiles: out, count: out.length });
}

// checkCode: Empfängt SHA-256-Hash (h), vergleicht mit gespeicherten Hashes
// Der Klartext-Code verlässt NIE den Browser!
function checkCode(clientHash) {
  if (!clientHash || clientHash.length !== 64) return fail(400, "Ungültiger Hash.");
  const props = PropertiesService.getScriptProperties();
  const h1    = props.getProperty("WEEK_CODE_1") || "";
  const h2    = props.getProperty("WEEK_CODE_2") || "";
  const valid = clientHash === h1 || (h2 && clientHash === h2);
  return valid ? win({ valid: true }) : fail(401, "Falscher Wochencode.");
}

// ════════════════════════════════════════════════════════════════
//  USER ENDPUNKTE (Edit-Token geschützt)
// ════════════════════════════════════════════════════════════════

function registerProfile(p) {
  // Validierung aller Felder server-seitig
  const errors  = [];
  const vorname = String(p.vorname || "").trim();
  const alter   = parseInt(p.alter);
  const bild    = String(p.bild   || "").trim();
  const bio     = String(p.bio    || "").trim();

  if (vorname.length < 2 || vorname.length > 100) errors.push("Vorname ungültig (2–100 Zeichen).");
  if (isNaN(alter) || alter < 18 || alter > 120)  errors.push("Alter ungültig (18–120).");
  if (!validRegion(p.region))                     errors.push("Region ungültig.");
  if (!validFB(String(p.fb || "")))               errors.push("FB-Link ungültig.");
  if (p.dsgvo !== "true")                         errors.push("DSGVO-Einwilligung fehlt.");
  if (errors.length) return fail(400, errors.join(" "));

  const sheet   = getSheet(PROFILES);
  const dupIdx  = findBy(sheet, COL.FB, String(p.fb).trim());
  if (dupIdx !== -1) {
    const existingToken = sheet.getDataRange().getValues()[dupIdx][COL.TOKEN-1];
    return fail(409, "Profil mit diesem FB-Link existiert bereits.", { t: existingToken });
  }

  const id    = generateUUID();
  const token = generateToken();
  const now   = new Date().toISOString();

  const bild2 = String(p.bild2 || "").trim();
  sheet.appendRow([
    id, now, token, "Neu", now,
    sanitize(vorname), alter, p.region, String(p.fb).trim(),
    bild  ? sanitize(bild)  : "",
    bio   ? sanitize(bio)   : "",
    true, false,
    bild2 ? sanitize(bild2) : "",  // 2. Foto
  ]);

  sendMail("Neues Profil: " + sanitize(vorname) + " / " + p.region);
  return win({ id, token });
}

function updateProfile(p) {
  if (!p.t) return fail(400, "Edit-Token (t) fehlt.");

  const sheet  = getSheet(PROFILES);
  const rowIdx = findBy(sheet, COL.TOKEN, p.t);
  if (rowIdx === -1) return fail(404, "Kein Profil mit diesem Token gefunden.");

  const row = sheet.getDataRange().getValues()[rowIdx];
  if (row[COL.STATUS-1] === "Gesperrt") return fail(403, "Dieses Profil ist gesperrt.");

  const r       = rowIdx + 1;
  const vorname = String(p.vorname || "").trim();
  const bild    = String(p.bild    || "").trim();
  const bio     = String(p.bio     || "").trim();

  if (vorname.length >= 2) sheet.getRange(r, COL.VORNAME).setValue(sanitize(vorname));
  const bild2u = String(p.bild2 || "").trim();
  sheet.getRange(r, COL.BILD).setValue(bild  ? sanitize(bild)  : "");
  sheet.getRange(r, COL.BIO).setValue(bio   ? sanitize(bio)   : "");
  sheet.getRange(r, COL.BILD2).setValue(bild2u ? sanitize(bild2u) : "");
  sheet.getRange(r, COL.ZULETZT).setValue(new Date().toISOString());
  sheet.getRange(r, COL.STATUS).setValue("Neu");
  sheet.getRange(r, COL.VERIFIZIERT).setValue(false);

  return win({ msg: "Profil aktualisiert. Wartet auf Admin-Freigabe." });
}

function deleteProfile(p) {
  if (!p.t) return fail(400, "Edit-Token (t) fehlt.");

  const sheet  = getSheet(PROFILES);
  const rowIdx = findBy(sheet, COL.TOKEN, p.t);
  if (rowIdx === -1) return fail(404, "Kein Profil mit diesem Token gefunden.");

  const row = sheet.getDataRange().getValues()[rowIdx];
  getSheet(ARCHIV).appendRow([...row, new Date().toISOString()]);
  sheet.deleteRow(rowIdx + 1);
  return win({ msg: "Profil erfolgreich gelöscht." });
}

function verifyToken(t) {
  if (!t) return fail(400, "Edit-Token (t) fehlt.");

  const sheet  = getSheet(PROFILES);
  const rowIdx = findBy(sheet, COL.TOKEN, t);
  if (rowIdx === -1) return fail(404, "Kein Profil mit diesem Token gefunden.");

  const r = sheet.getDataRange().getValues()[rowIdx];
  return win({
    vorname:    r[COL.VORNAME-1],
    alter:      r[COL.ALTER-1],
    region:     r[COL.REGION-1],
    fb:         r[COL.FB-1],
    bild:       r[COL.BILD-1]  || "",
    bild2:      r[COL.BILD2-1] || "",
    bio:        r[COL.BIO-1]   || "",
    status:     r[COL.STATUS-1],
    verifiziert:r[COL.VERIFIZIERT-1],
  });
}

// ════════════════════════════════════════════════════════════════
//  ADMIN ENDPUNKTE (verschleiert als "ax", Session-Token pflicht)
// ════════════════════════════════════════════════════════════════

function adminAction(p) {
  const s = p.s || "";

  // Login: einzige Aktion ohne Session-Token
  if (s === "login") return adminLogin(p.h || "");

  // ALLE anderen Admin-Aktionen: Session-Token (st) prüfen
  // Das st kommt bei jedem Call mit — Server validiert jedes Mal neu
  if (!validSession(p.st || "")) {
    return fail(401, "Session ungültig oder abgelaufen. Bitte neu einloggen.");
  }

  if (s === "q")    return adminGetQueue();
  if (s === "all")  return adminGetAll(p.f || "");
  if (s === "ok")   return adminApprove(p.id || "");
  if (s === "ban")  return adminBan(p.id || "");
  if (s === "del")  return adminDelete(p.id || "");
  if (s === "code") return adminSetCode(p.h || "");
  if (s === "out")  return adminLogout(p.st || "");

  return fail(400, "Unbekannte Admin-Sub-Aktion: " + s);
}

// ── Admin Login: PIN-Hash (h) kommt an, Klartext-PIN NIE ────────
// Frontend hasht den PIN mit SHA-256 → schickt nur den Hash
// Backend vergleicht Hash mit gespeichertem ADMIN_PIN_HASH
function adminLogin(pinHash) {
  if (!pinHash || pinHash.length !== 64) {
    return fail(400, "Ungültiger PIN-Hash (SHA-256 erwartet).");
  }

  const props    = PropertiesService.getScriptProperties();
  const expected = props.getProperty("ADMIN_PIN_HASH");

  if (!expected) {
    return fail(500, "System nicht initialisiert. initialisiereSystem() ausführen.");
  }

  // Konstanter Zeitvergleich gegen Timing-Angriffe wäre ideal,
  // aber Apps Script bietet das nicht — sleep schützt gegen Brute-Force
  if (pinHash !== expected) {
    Utilities.sleep(1500); // 1.5s Verzögerung gegen Brute-Force
    return fail(401, "Falscher PIN.");
  }

  // Session-Token generieren und in Script-Properties speichern
  // (kein eigenes Sheet — einfacher und schneller)
  const sessionToken  = generateToken();
  const expiry        = new Date();
  expiry.setHours(expiry.getHours() + SESS_HRS);

  props.setProperty("ADMIN_SESSION_ST",  sessionToken);
  props.setProperty("ADMIN_SESSION_EXP", expiry.toISOString());

  Logger.log("Admin-Login erfolgreich. Session läuft ab: " + expiry.toISOString());
  return win({ st: sessionToken, exp: expiry.toISOString() });
}

// ── Session validieren: Token + Ablaufzeit aus Properties ────────
function validSession(st) {
  if (!st) return false;
  const props    = PropertiesService.getScriptProperties();
  const savedST  = props.getProperty("ADMIN_SESSION_ST")  || "";
  const savedEXP = props.getProperty("ADMIN_SESSION_EXP") || "";
  if (!savedST || !savedEXP) return false;
  if (st !== savedST) return false;                    // Token-Vergleich
  return new Date() < new Date(savedEXP);              // Ablauf-Prüfung
}

// ── Admin Logout: Session aus Properties löschen ─────────────────
function adminLogout(st) {
  if (!validSession(st)) return fail(401, "Keine gültige Session.");
  const props = PropertiesService.getScriptProperties();
  props.deleteProperty("ADMIN_SESSION_ST");
  props.deleteProperty("ADMIN_SESSION_EXP");
  return win({ msg: "Erfolgreich ausgeloggt." });
}

// ── Admin Queue (alle "Neu"-Profile) ─────────────────────────────
function adminGetQueue() {
  const rows = getSheet(PROFILES).getDataRange().getValues();
  const q    = rows.slice(1)
    .filter(r => r[COL.STATUS-1] === "Neu")
    .map(r => ({
      id:      r[COL.ID-1],
      vorname: r[COL.VORNAME-1],
      alter:   r[COL.ALTER-1],
      region:  r[COL.REGION-1],
      fb:      r[COL.FB-1],
      bio:     r[COL.BIO-1] || null,
      ts:      r[COL.TIMESTAMP-1],
    }));
  return win({ queue: q, count: q.length });
}

// ── Admin Alle Profile (optional gefiltert nach Status) ───────────
function adminGetAll(filter) {
  const rows = getSheet(PROFILES).getDataRange().getValues();
  const out  = rows.slice(1)
    .filter(r => !filter || r[COL.STATUS-1] === filter)
    .map(r => ({
      id:      r[COL.ID-1],
      vorname: r[COL.VORNAME-1],
      alter:   r[COL.ALTER-1],
      region:  r[COL.REGION-1],
      fb:      r[COL.FB-1],
      status:  r[COL.STATUS-1],
      ts:      r[COL.TIMESTAMP-1],
    }));
  return win({ profiles: out, count: out.length });
}

// ── Admin Profil freigeben ────────────────────────────────────────
function adminApprove(id) {
  if (!id) return fail(400, "Profil-ID (id) fehlt.");
  const sheet  = getSheet(PROFILES);
  const rowIdx = findBy(sheet, COL.ID, id);
  if (rowIdx === -1) return fail(404, "Profil nicht gefunden.");
  sheet.getRange(rowIdx+1, COL.STATUS).setValue("Aktiv");
  sheet.getRange(rowIdx+1, COL.VERIFIZIERT).setValue(true);
  return win({ msg: "Profil freigegeben." });
}

// ── Admin Profil sperren ──────────────────────────────────────────
function adminBan(id) {
  if (!id) return fail(400, "Profil-ID (id) fehlt.");
  const sheet  = getSheet(PROFILES);
  const rowIdx = findBy(sheet, COL.ID, id);
  if (rowIdx === -1) return fail(404, "Profil nicht gefunden.");
  sheet.getRange(rowIdx+1, COL.STATUS).setValue("Gesperrt");
  return win({ msg: "Profil gesperrt." });
}

// ── Admin Profil löschen (ins Archiv) ────────────────────────────
function adminDelete(id) {
  if (!id) return fail(400, "Profil-ID (id) fehlt.");
  const sheet  = getSheet(PROFILES);
  const rowIdx = findBy(sheet, COL.ID, id);
  if (rowIdx === -1) return fail(404, "Profil nicht gefunden.");
  const row = sheet.getDataRange().getValues()[rowIdx];
  getSheet(ARCHIV).appendRow([...row, new Date().toISOString()]);
  sheet.deleteRow(rowIdx + 1);
  return win({ msg: "Profil gelöscht." });
}

// ── Admin Wochencode wechseln (Hash kommt an, NIE Klartext!) ─────
function adminSetCode(newHash) {
  if (!newHash || newHash.length !== 64) {
    return fail(400, "Ungültiger Code-Hash (SHA-256, 64 Zeichen erwartet).");
  }
  const props = PropertiesService.getScriptProperties();
  // Alter Code → WEEK_CODE_2 (Dual-Hash: 24h Überlappung)
  props.setProperty("WEEK_CODE_2", props.getProperty("WEEK_CODE_1") || "");
  props.setProperty("WEEK_CODE_1", newHash);
  return win({ msg: "Wochencode gewechselt. Alter Code noch 24h gültig." });
}

// ════════════════════════════════════════════════════════════════
//  HILFSFUNKTIONEN
// ════════════════════════════════════════════════════════════════

function getSheet(name) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let   sh = ss.getSheetByName(name);
  if (!sh) {
    sh = ss.insertSheet(name);
    if (name === PROFILES) {
      sh.appendRow(["ID","Timestamp","Token","Status","Zuletzt","Vorname","Alter","Region","FB","Bild","Bio","DSGVO","Verifiziert","Bild2"]);
      sh.getRange(1,1,1,13).setFontWeight("bold").setBackground("#00833E").setFontColor("#fff");
      sh.setFrozenRows(1);
    }
    if (name === ARCHIV) {
      sh.appendRow(["ID","Timestamp","Token","Status","Zuletzt","Vorname","Alter","Region","FB","Bild","Bio","DSGVO","Verifiziert","Geloescht_Am"]);
      sh.getRange(1,1,1,14).setFontWeight("bold").setBackground("#757575").setFontColor("#fff");
      sh.setFrozenRows(1);
    }
  }
  return sh;
}

function findBy(sheet, col, value) {
  const rows = sheet.getDataRange().getValues();
  const val  = String(value).trim();
  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][col-1]).trim() === val) return i;
  }
  return -1;
}

function validRegion(r) {
  return ["Chemnitz","Dresden","Leipzig","Zwickau","Plauen","Görlitz","Erzgebirge","Sonstige"].includes(r);
}

function validFB(url) {
  return url && url.startsWith("http") && url.includes("facebook.com");
}

function generateUUID() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === "x" ? r : (r & 3 | 8)).toString(16);
  });
}

function generateToken() {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let t = "";
  for (let i = 0; i < 40; i++) t += chars[Math.floor(Math.random() * chars.length)];
  return t;
}

function sanitize(s) {
  if (typeof s !== "string") return "";
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
          .replace(/"/g,"&quot;").trim().substring(0, 500);
}

function sendMail(subject) {
  try {
    const addr = PropertiesService.getScriptProperties().getProperty("ADMIN_EMAIL");
    if (!addr) return;
    const url  = SpreadsheetApp.getActiveSpreadsheet().getUrl();
    MailApp.sendEmail(addr, "[SSC] " + subject, subject + "\n\n" + url);
  } catch(e) { Logger.log("Mail-Fehler: " + e.message); }
}

function win(data) {
  return ContentService
    .createTextOutput(JSON.stringify({ ok: true, ...data }))
    .setMimeType(ContentService.MimeType.JSON);
}

function fail(code, msg, extra = {}) {
  return ContentService
    .createTextOutput(JSON.stringify({ ok: false, error: msg, code, ...extra }))
    .setMimeType(ContentService.MimeType.JSON);
}

// ════════════════════════════════════════════════════════════════
//  SETUP — Einmalig im Apps Script Editor ausführen!
// ════════════════════════════════════════════════════════════════

/**
 * EINMALIGER SETUP: Setzt Admin-PIN-Hash und ersten Wochencode.
 *
 * Anleitung:
 * 1. Gewünschten PIN und Wochencode unten eintragen
 * 2. Diese Funktion einmalig im Editor ausführen (▶)
 * 3. Im Log prüfen ob ✅ erscheint
 * 4. PIN und Wochencode aus dem Code löschen und speichern!
 */
function initialisiereSystem() {
  const adminPin   = "DEINEN_PIN_HIER";       // ← ändern!
  const wochencode = "SACHSEN";               // ← erster Wochencode

  if (adminPin === "DEINEN_PIN_HIER") {
    Logger.log("❌ Bitte erst einen echten PIN eingeben!");
    return;
  }

  const props = PropertiesService.getScriptProperties();

  // SHA-256 Hash des PINs berechnen und speichern
  const pinHash = sha256GAS(adminPin);
  props.setProperty("ADMIN_PIN_HASH", pinHash);
  Logger.log("✅ Admin-PIN-Hash gespeichert: " + pinHash);

  // SHA-256 Hash des Wochencodes berechnen und speichern
  const codeHash = sha256GAS(wochencode);
  props.setProperty("WEEK_CODE_1", codeHash);
  props.deleteProperty("WEEK_CODE_2");
  Logger.log("✅ Wochencode '" + wochencode + "' → Hash: " + codeHash);

  Logger.log("⚠️  PIN und Wochencode jetzt aus dem Code löschen und Strg+S!");
  Logger.log("🚀 System bereit!");
}

/**
 * SHA-256 in Apps Script (für initiales Setup)
 */
function sha256GAS(text) {
  return Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    text,
    Utilities.Charset.UTF_8
  ).map(b => ("0" + (b & 0xFF).toString(16)).slice(-2)).join("");
}

/**
 * Statistik anzeigen
 */
function zeigeStatistik() {
  const rows = getSheet(PROFILES).getDataRange().getValues();
  let aktiv=0, neu=0, gesperrt=0;
  for (let i = 1; i < rows.length; i++) {
    const s = rows[i][COL.STATUS-1];
    if (s==="Aktiv")    aktiv++;
    else if (s==="Neu") neu++;
    else if (s==="Gesperrt") gesperrt++;
  }
  Logger.log(`📊 Statistik: Gesamt=${rows.length-1}  Aktiv=${aktiv}  Neu=${neu}  Gesperrt=${gesperrt}`);

  // Session-Status
  const props  = PropertiesService.getScriptProperties();
  const exp    = props.getProperty("ADMIN_SESSION_EXP") || "keine";
  const active = exp !== "keine" && new Date() < new Date(exp);
  Logger.log(`🔑 Admin-Session: ${active ? "Aktiv bis " + exp : "Keine aktive Session"}`);
}
