// BadgyTOTP: TOTP authenticator for the Badgy e-paper badge (Rev 2B or older by default; build
// the badgy_rev2c environment for the Rev 2C panel).
//
// Normal boot:  join saved WiFi -> sync time -> WiFi off -> show codes -> sleep after 2 min idle.
// Centre held at power-on (or no WiFi saved): setup mode, which serves the secrets page.

#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WebServer.h>
#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <LittleFS.h>
#include <MD5Builder.h>
#include <WiFiManager.h>
#include <time.h>

#include <GxEPD.h>
#ifdef BADGY_REV2C
#include <GxGDEW029T5/GxGDEW029T5.h>  // Rev 2C: asterisk jumper, green film tab
#else
#include <GxGDEH029A1/GxGDEH029A1.h>  // Rev 2B and older
#endif
#include <GxIO/GxIO.h>
#include <GxIO/GxIO_SPI/GxIO_SPI.h>
#include <Fonts/FreeMonoBold24pt7b.h>
#include <Fonts/FreeSans9pt7b.h>
#include <Fonts/FreeSansBold9pt7b.h>

#include <vector>

#include "totp.h"

// ---- Hardware -------------------------------------------------------------------------------

GxIO_Class io(SPI, SS, 0, 2);  // CS=15, DC=0, RST=2 (Badgy wiring)
GxEPD_Class display(io);       // RST=2, BUSY=4

enum Button : uint8_t { BTN_DOWN, BTN_LEFT, BTN_CENTRE, BTN_RIGHT, BTN_UP, BTN_COUNT };
const uint8_t BUTTON_PINS[BTN_COUNT] = {1, 3, 5, 12, 10};  // active low; 1/3 are the UART

// ---- Configuration --------------------------------------------------------------------------

const char *DEFAULT_TZ = "UTC0";  // POSIX TZ for the on-screen clock only; TOTP always uses UTC
const time_t MIN_VALID_TIME = 1735689600;             // 2025-01-01: anything earlier is unsynced
const uint32_t IDLE_SLEEP_MS = 120000;
const uint32_t SETUP_IDLE_MS = 600000;
const uint32_t WIFI_TIMEOUT_MS = 15000;
const uint32_t NTP_TIMEOUT_MS = 10000;
const size_t MAX_ACCOUNTS = 24;
const char *ADMIN_USER = "admin";
const char *REALM = "BadgyTOTP";
const char *AP_NAME = "Badgy-TOTP";
const char *HOSTNAME = "badgy-totp";

// ---- State ----------------------------------------------------------------------------------

struct Account {
  String issuer;
  String label;
  String secret;  // normalised base32
  uint8_t digits;
  uint8_t period;
};

std::vector<Account> accounts;
size_t selected = 0;
size_t savedSelected = 0;
bool timeSynced = false;
String note;  // transient bottom-right message ("sent to PC", "no PC app")
uint32_t noteUntil = 0;
uint32_t bridgeSeenAt = 0;  // millis() of the last heartbeat from the PC bridge
const uint32_t BRIDGE_TIMEOUT_MS = 5000;

bool bridgePresent() { return bridgeSeenAt && millis() - bridgeSeenAt < BRIDGE_TIMEOUT_MS; }

// ---- Display helpers ------------------------------------------------------------------------

int16_t textWidth(const String &s, const GFXfont *font) {
  int16_t x1, y1;
  uint16_t w, h;
  display.setFont(font);
  display.getTextBounds(s.c_str(), 0, 0, &x1, &y1, &w, &h);
  return w;
}

void drawText(const String &s, const GFXfont *font, int16_t x, int16_t y) {
  display.setFont(font);
  display.setCursor(x, y);
  display.print(s);
}

void drawCentred(const String &s, const GFXfont *font, int16_t y) {
  drawText(s, font, (display.width() - textWidth(s, font)) / 2, y);
}

String fitText(String s, const GFXfont *font, int16_t maxW) {
  if (textWidth(s, font) <= maxW) return s;
  while (s.length() > 1 && textWidth(s + "..", font) > maxW) s.remove(s.length() - 1);
  return s + "..";
}

// Full-refresh message screen: a bold title plus up to four plain lines.
void showMessage(const String &title, const String &l1 = "", const String &l2 = "",
                 const String &l3 = "", const String &l4 = "") {
  display.setRotation(3);
  display.fillScreen(GxEPD_WHITE);
  display.setTextColor(GxEPD_BLACK);
  drawText(title, &FreeSansBold9pt7b, 4, 18);
  display.drawFastHLine(0, 24, display.width(), GxEPD_BLACK);
  const String *lines[] = {&l1, &l2, &l3, &l4};
  for (int i = 0; i < 4; i++) drawText(fitText(*lines[i], &FreeSans9pt7b, 288), &FreeSans9pt7b, 4, 46 + i * 22);
  display.update();
}

String groupCode(const std::string &code) {
  String s(code.c_str());
  if (s.length() == 6) return s.substring(0, 3) + " " + s.substring(3);
  if (s.length() == 8) return s.substring(0, 4) + " " + s.substring(4);
  return s;
}

std::string codeFor(const Account &a, time_t t) {
  uint8_t key[64];
  int n = totp::base32Decode(a.secret.c_str(), key, sizeof(key));
  if (n <= 0) return "------";
  return totp::formatCode(totp::totpAt(key, n, (uint64_t)t, a.period, a.digits), a.digits);
}

// Draws the code screen for the selected account into the buffer.
void drawCodeScreen(time_t now) {
  const Account &a = accounts[selected];
  int remaining = a.period - (int)(now % a.period);

  display.setRotation(3);
  display.fillScreen(GxEPD_WHITE);
  display.setTextColor(GxEPD_BLACK);

  struct tm local;
  localtime_r(&now, &local);
  char clock[6];
  strftime(clock, sizeof(clock), "%H:%M", &local);
  String pos = String(selected + 1) + "/" + String(accounts.size());

  drawText(clock, &FreeSans9pt7b, display.width() - textWidth(clock, &FreeSans9pt7b) - 4, 16);
  drawText(fitText(a.issuer.length() ? a.issuer : a.label, &FreeSansBold9pt7b, 220), &FreeSansBold9pt7b, 4, 16);
  drawText(pos, &FreeSans9pt7b, display.width() - textWidth(pos, &FreeSans9pt7b) - 4, 36);
  if (a.issuer.length()) drawText(fitText(a.label, &FreeSans9pt7b, 240), &FreeSans9pt7b, 4, 36);

  drawCentred(groupCode(codeFor(a, now)), &FreeMonoBold24pt7b, 84);

  int barW = (display.width() - 8) * remaining / a.period;
  display.drawRect(4, 96, display.width() - 8, 8, GxEPD_BLACK);
  display.fillRect(4, 96, barW, 8, GxEPD_BLACK);

  drawText(String(remaining) + "s", &FreeSans9pt7b, 4, 123);
  if (millis() < noteUntil) {
    drawText(note, &FreeSansBold9pt7b, display.width() - textWidth(note, &FreeSansBold9pt7b) - 4, 123);
  } else if (remaining <= 7) {
    String next = "next " + groupCode(codeFor(a, now + remaining));
    drawText(next, &FreeSansBold9pt7b, display.width() - textWidth(next, &FreeSansBold9pt7b) - 4, 123);
  } else {
    String hint;
    if (bridgePresent()) {
      hint = accounts.size() > 1 ? "right: type  up/dn: acct" : "right: type on PC";
    } else if (accounts.size() > 1) {
      hint = "up/down: account";
    }
    drawText(hint, &FreeSans9pt7b, display.width() - textWidth(hint, &FreeSans9pt7b) - 4, 123);
  }
}

void showNote(const String &text) {
  note = text;
  noteUntil = millis() + 3000;
}

// In normal mode UART0 runs receive-only on GPIO3 (the left button's pin, now unused), so the
// badge can hear the bridge while GPIO1 stays free to be the down button.
void serialListen() {
  Serial.begin(115200, SERIAL_8N1, SERIAL_RX_ONLY);
  pinMode(BUTTON_PINS[BTN_DOWN], INPUT_PULLUP);
}

// Reads bridge heartbeats ("#BRIDGE:HELLO"). Anything else, including the garbage a pressed
// left button makes on the RX line, is discarded.
void pollBridge() {
  static String line;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n') {
      line.trim();
      if (line == "#BRIDGE:HELLO") bridgeSeenAt = millis();
      line = "";
    } else if (line.length() < 32) {
      line += c;
    } else {
      line = "";
    }
  }
}

// Sends the selected code to the PC bridge over the USB serial link. GPIO1 is both UART TX and
// the down button, so TX is claimed only for the few milliseconds the line takes, then the pin
// goes back to being a button. The bridge acts only on lines matching "#BADGYTOTP:<digits>".
void sendCodeToPc() {
  if (!bridgePresent()) return showNote("no PC app");
  const Account &a = accounts[selected];
  time_t now = time(nullptr);
  if (a.period - (int)(now % a.period) <= 2) {  // too close to expiry to type in time: wait for the next one
    while (time(nullptr) / a.period == now / a.period) delay(20);
    now = time(nullptr);
  }
  Serial.end();
  Serial.begin(115200, SERIAL_8N1, SERIAL_FULL);
  Serial.printf("\n#BADGYTOTP:%s\n", codeFor(a, now).c_str());
  Serial.flush();
  Serial.end();
  serialListen();
  showNote("sent to PC");
}

// ---- Storage --------------------------------------------------------------------------------

void loadAccounts() {
  accounts.clear();
  File f = LittleFS.open("/accounts.json", "r");
  if (!f) return;
  JsonDocument doc;
  if (deserializeJson(doc, f)) return;
  for (JsonObject o : doc.as<JsonArray>()) {
    Account a{o["issuer"] | "", o["label"] | "", o["secret"] | "", (uint8_t)(o["digits"] | 6),
              (uint8_t)(o["period"] | 30)};
    if (a.secret.length()) accounts.push_back(a);
  }
}

bool saveAccounts() {
  JsonDocument doc;
  JsonArray arr = doc.to<JsonArray>();
  for (const Account &a : accounts) {
    JsonObject o = arr.add<JsonObject>();
    o["issuer"] = a.issuer;
    o["label"] = a.label;
    o["secret"] = a.secret;
    o["digits"] = a.digits;
    o["period"] = a.period;
  }
  File f = LittleFS.open("/accounts.json.tmp", "w");
  if (!f) return false;
  bool ok = serializeJson(doc, f) > 0;
  f.close();
  return ok && LittleFS.rename("/accounts.json.tmp", "/accounts.json");
}

String readSmallFile(const char *path) {
  File f = LittleFS.open(path, "r");
  if (!f) return "";
  String s = f.readString();
  s.trim();
  return s;
}

void writeSmallFile(const char *path, const String &s) {
  File f = LittleFS.open(path, "w");
  if (f) f.print(s);
}

String tzInfo() {
  String tz = readSmallFile("/tz");
  return tz.length() ? tz : DEFAULT_TZ;
}

// ---- Sleep ----------------------------------------------------------------------------------

void goToSleep(const String &why) {
  if (selected != savedSelected) writeSmallFile("/selected", String(selected));
  showMessage("Asleep", why, "", "Slide the power switch off and", "on again to show codes.");
  display.powerDown();
  WiFi.mode(WIFI_OFF);
  ESP.deepSleep(0);  // buttons cannot wake the ESP8266; only the power switch (reset) does
}

// ---- Time -----------------------------------------------------------------------------------

// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm), so no timegm() needed.
int64_t daysFromCivil(int y, int m, int d) {
  y -= m <= 2;
  int era = (y >= 0 ? y : y - 399) / 400;
  int yoe = y - era * 400;
  int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return (int64_t)era * 146097 + doe - 719468;
}

// Parses an HTTP Date header, e.g. "Mon, 28 Sep 2026 00:12:34 GMT". Returns 0 on failure.
time_t parseHttpDate(const String &s) {
  static const char *MONTHS = "JanFebMarAprMayJunJulAugSepOctNovDec";
  char mon[4] = {0};
  int d, y, hh, mm, ss;
  if (sscanf(s.c_str(), "%*3s, %d %3s %d %d:%d:%d", &d, mon, &y, &hh, &mm, &ss) != 6) return 0;
  const char *p = strstr(MONTHS, mon);
  if (!p) return 0;
  int m = (p - MONTHS) / 3 + 1;
  return (time_t)(daysFromCivil(y, m, d) * 86400 + hh * 3600 + mm * 60 + ss);
}

// Fallback for networks that block NTP (UDP 123): take the Date header from a plain HTTP fetch.
bool syncFromHttpDate() {
  WiFiClient client;
  HTTPClient http;
  const char *keys[] = {"Date"};
  if (!http.begin(client, "http://www.google.com/generate_204")) return false;
  http.collectHeaders(keys, 1);
  int code = http.GET();
  time_t t = code > 0 ? parseHttpDate(http.header("Date")) : 0;
  http.end();
  if (t < MIN_VALID_TIME) return false;
  timeval tv{t, 0};
  settimeofday(&tv, nullptr);
  Serial.printf("[time] HTTP Date fallback: %ld\n", (long)t);
  return true;
}

bool syncTime() {
  configTime(tzInfo().c_str(), "time.google.com", "pool.ntp.org", "time.cloudflare.com");
  uint32_t start = millis();
  while (millis() - start < NTP_TIMEOUT_MS) {
    if (time(nullptr) > MIN_VALID_TIME) {
      Serial.printf("[time] NTP synced in %lu ms: %ld\n", millis() - start, (long)time(nullptr));
      return true;
    }
    delay(100);
  }
  Serial.println("[time] NTP timed out, trying HTTP Date");
  return syncFromHttpDate();
}

// ---- Setup mode -----------------------------------------------------------------------------

ESP8266WebServer server(80);
String sessionPin;
String csrfToken;
uint8_t pinFailures = 0;
uint32_t setupLastActivity = 0;
String flash;  // one-shot status message for the next page render

String randomDigits(int n) {
  String s;
  for (int i = 0; i < n; i++) s += (char)('0' + ESP.random() % 10);
  return s;
}

String randomHex(int bytes) {
  String s;
  char b[3];
  for (int i = 0; i < bytes; i++) {
    snprintf(b, sizeof(b), "%02x", (uint8_t)ESP.random());
    s += b;
  }
  return s;
}

String htmlEscape(const String &in) {
  String s;
  for (char c : in) {
    switch (c) {
      case '&': s += F("&amp;"); break;
      case '<': s += F("&lt;"); break;
      case '>': s += F("&gt;"); break;
      case '"': s += F("&quot;"); break;
      case '\'': s += F("&#39;"); break;
      default: s += c;
    }
  }
  return s;
}

void showSetupScreen() {
  String ip = WiFi.localIP().toString();
  showMessage("SETUP MODE  PIN " + sessionPin, "http://" + ip, String("http://") + HOSTNAME + ".local",
              readSmallFile("/admin").length() ? "Login: admin + your password" : "First visit: set a password",
              "Turns off after 10 min idle");
}

const char PAGE_HEAD[] PROGMEM = R"(<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>BadgyTOTP</title><style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:0 auto;padding:16px;color:#111;background:#fafafa}
h1{font-size:1.4em}h2{font-size:1.1em;margin-top:1.6em}table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:6px;border-bottom:1px solid #ddd}input,button{font:inherit;padding:6px}
input[type=text],input[type=password]{width:100%;box-sizing:border-box;margin:4px 0 10px}
.flash{background:#fff3c4;padding:8px;border-radius:4px}.muted{color:#666;font-size:.9em}
button.danger{color:#b00}</style></head><body><h1>BadgyTOTP</h1>)";

void sendPage(const String &body) {
  String html = FPSTR(PAGE_HEAD);
  if (flash.length()) html += "<p class=flash>" + htmlEscape(flash) + "</p>";
  flash = "";
  html += body + "</body></html>";
  server.sendHeader("Cache-Control", "no-store");
  server.sendHeader("X-Frame-Options", "DENY");
  server.send(200, "text/html", html);
}

void redirectHome() {
  server.sendHeader("Location", "/");
  server.send(303);
}

void touchSetup() { setupLastActivity = millis(); }

bool hasPassword() { return readSmallFile("/admin").length() == 32; }

// Digest auth, so the password never crosses the network in the clear.
bool requireAuth() {
  touchSetup();
  if (!hasPassword()) {
    server.sendHeader("Location", "/setpw");
    server.send(303);
    return false;
  }
  if (server.authenticateDigest(ADMIN_USER, readSmallFile("/admin"))) return true;
  server.requestAuthentication(DIGEST_AUTH, REALM, "Wrong password");
  return false;
}

bool checkCsrf() {
  if (server.arg("csrf") == csrfToken) return true;
  server.send(403, "text/plain", "Stale form, reload the page");
  return false;
}

void handleRoot() {
  if (!requireAuth()) return;
  String b = "<h2>Accounts</h2>";
  if (accounts.empty()) {
    b += "<p class=muted>No accounts yet.</p>";
  } else {
    b += "<table><tr><th>Issuer</th><th>Account</th><th>Digits/period</th><th></th></tr>";
    for (size_t i = 0; i < accounts.size(); i++) {
      const Account &a = accounts[i];
      b += "<tr><td>" + htmlEscape(a.issuer) + "</td><td>" + htmlEscape(a.label) + "</td><td>" + a.digits + " / " +
           a.period + "s</td><td><form method=post action=/del onsubmit=\"return confirm('Delete this account?')\">"
           "<input type=hidden name=csrf value=" + csrfToken + "><input type=hidden name=i value=" + i +
           "><button class=danger>Delete</button></form></td></tr>";
    }
    b += "</table>";
  }
  b += "<h2>Add account</h2><form method=post action=/add><input type=hidden name=csrf value=" + csrfToken + ">"
       "<label>otpauth:// URI (from a QR code), <b>or</b> fill in the fields below"
       "<input type=text name=uri autocomplete=off placeholder=\"otpauth://totp/...\"></label>"
       "<label>Issuer<input type=text name=issuer placeholder=\"Google\"></label>"
       "<label>Account<input type=text name=label placeholder=\"shared@example.com\"></label>"
       "<label>Secret key (base32, spaces are fine)"
       "<input type=password name=secret autocomplete=off></label><button>Add</button></form>";
  b += "<h2>Backup</h2><form method=post action=/backup><input type=hidden name=csrf value=" + csrfToken + ">"
       "<label>PIN shown on the badge<input type=text name=pin inputmode=numeric autocomplete=off></label>"
       "<button>Download backup</button></form><p class=muted>A plain text file of otpauth:// links. Anyone "
       "holding it can generate the codes, so keep it somewhere safe. The PIN changes after each download.</p>";
  b += "<h2>Restore</h2><form method=post action=/restore><input type=hidden name=csrf value=" + csrfToken + ">"
       "<label>Backup file <input type=file accept=\".txt,text/plain\" "
       "onchange=\"var r=new FileReader();r.onload=function(){document.getElementById('uris').value=r.result};"
       "r.readAsText(this.files[0])\"></label>"
       "<label>or paste otpauth:// links, one per line<textarea id=uris name=uris rows=5 style=width:100%;"
       "box-sizing:border-box></textarea></label>"
       "<label><input type=checkbox name=replace> Replace all existing accounts (otherwise merge)</label><br><br>"
       "<button>Restore</button></form>";
  b += "<h2>Clock timezone</h2><form method=post action=/tz><input type=hidden name=csrf value=" + csrfToken +
       "><label>POSIX TZ string (only affects the clock on the badge; codes are always UTC)"
       "<input type=text name=tz list=tzs value=\"" + htmlEscape(tzInfo()) + "\"></label><datalist id=tzs>"
       "<option value=UTC0>UTC</option><option value=\"GMT0BST,M3.5.0/1,M10.5.0\">London</option>"
       "<option value=\"CET-1CEST,M3.5.0,M10.5.0/3\">Central Europe</option>"
       "<option value=\"EST5EDT,M3.2.0,M11.1.0\">US Eastern</option>"
       "<option value=\"PST8PDT,M3.2.0,M11.1.0\">US Pacific</option><option value=SGT-8>Singapore</option>"
       "<option value=JST-9>Tokyo</option><option value=\"AEST-10AEDT,M10.1.0,M4.1.0/3\">Sydney/Melbourne</option>"
       "<option value=AEST-10>Brisbane</option><option value=\"NZST-12NZDT,M9.5.0,M4.1.0/3\">Auckland</option>"
       "</datalist><button>Save timezone</button></form>";
  b += "<h2>Device</h2><form method=post action=/done style=display:inline><input type=hidden name=csrf value=" +
       csrfToken + "><button>Finish and sleep</button></form> "
       "<form method=post action=/wifi-forget style=display:inline onsubmit=\"return confirm('Forget WiFi and reboot "
       "into the WiFi portal?')\"><input type=hidden name=csrf value=" + csrfToken +
       "><button class=danger>Forget WiFi</button></form>"
       "<p class=muted>To change the password, use <a href=/setpw>/setpw</a> with the PIN on the badge.</p>";
  sendPage(b);
}

void handleAdd() {
  if (!requireAuth() || !checkCsrf()) return;
  if (accounts.size() >= MAX_ACCOUNTS) {
    flash = "Account limit reached";
    return redirectHome();
  }
  Account a;
  String uri = server.arg("uri");
  uri.trim();
  if (uri.length()) {
    totp::OtpAuth parsed;
    std::string err;
    if (!totp::parseOtpAuth(uri.c_str(), parsed, err)) {
      flash = String("Not added: ") + err.c_str();
      return redirectHome();
    }
    a = {parsed.issuer.c_str(), parsed.label.c_str(), parsed.secret.c_str(), (uint8_t)parsed.digits,
         (uint8_t)parsed.period};
  } else {
    std::string secret = totp::normaliseBase32(server.arg("secret").c_str());
    uint8_t key[64];
    if (secret.empty() || totp::base32Decode(secret.c_str(), key, sizeof(key)) < 10) {
      flash = "Not added: the secret is not valid base32";
      return redirectHome();
    }
    a = {server.arg("issuer"), server.arg("label"), secret.c_str(), 6, 30};
    a.issuer.trim();
    a.label.trim();
  }
  if (!a.issuer.length() && !a.label.length()) a.label = "Account " + String(accounts.size() + 1);
  accounts.push_back(a);
  if (!saveAccounts()) {
    accounts.pop_back();
    flash = "Not added: could not write to flash";
  } else {
    flash = "Added " + (a.issuer.length() ? a.issuer + " " : "") + a.label;
    Serial.printf("[setup] added account %u\n", accounts.size());
  }
  redirectHome();
}

void handleDelete() {
  if (!requireAuth() || !checkCsrf()) return;
  size_t i = server.arg("i").toInt();
  if (server.arg("i").length() && i < accounts.size()) {
    Account removed = accounts[i];
    accounts.erase(accounts.begin() + i);
    if (saveAccounts()) {
      flash = "Deleted " + removed.issuer + " " + removed.label;
    } else {
      accounts.insert(accounts.begin() + i, removed);
      flash = "Delete failed: could not write to flash";
    }
  }
  redirectHome();
}

// The PIN shown on the badge proves physical presence. Five wrong tries rotate it.
bool checkPin() {
  if (server.arg("pin") == sessionPin) return true;
  if (++pinFailures >= 5) {
    sessionPin = randomDigits(6);
    pinFailures = 0;
    showSetupScreen();
  }
  flash = "Wrong PIN";
  return false;
}

// PIN is single use: rotate it and put the new one on the badge.
void rotatePin() {
  sessionPin = randomDigits(6);
  pinFailures = 0;
  showSetupScreen();
}

totp::OtpAuth toOtpAuth(const Account &a) {
  totp::OtpAuth o;
  o.issuer = a.issuer.c_str();
  o.label = a.label.c_str();
  o.secret = a.secret.c_str();
  o.digits = a.digits;
  o.period = a.period;
  return o;
}

// Plain-text backup: one otpauth:// URI per line, importable by any authenticator app.
void handleBackup() {
  if (!requireAuth() || !checkCsrf()) return;
  if (!checkPin()) return redirectHome();
  rotatePin();
  String body;
  for (const Account &a : accounts) body += String(totp::buildOtpAuth(toOtpAuth(a)).c_str()) + "\n";
  time_t now = time(nullptr);
  char name[48];
  if (now > MIN_VALID_TIME) {
    struct tm local;
    localtime_r(&now, &local);
    strftime(name, sizeof(name), "badgy-totp-backup-%Y%m%d.txt", &local);
  } else {
    strcpy(name, "badgy-totp-backup.txt");
  }
  server.sendHeader("Content-Disposition", String("attachment; filename=\"") + name + "\"");
  server.sendHeader("Cache-Control", "no-store");
  server.send(200, "text/plain; charset=utf-8", body);
  Serial.printf("[setup] backup downloaded, %u account(s)\n", accounts.size());
}

// Restore from a backup (or any list of otpauth:// URIs). Merges by default, skipping secrets
// already on the device; "replace" wipes the existing accounts first.
void handleRestore() {
  if (!requireAuth() || !checkCsrf()) return;
  bool replace = server.hasArg("replace");
  std::vector<Account> next = replace ? std::vector<Account>() : accounts;
  int added = 0, duplicate = 0, invalid = 0, overLimit = 0;
  String text = server.arg("uris");
  int start = 0;
  while (start < (int)text.length()) {
    int end = text.indexOf('\n', start);
    if (end < 0) end = text.length();
    String line = text.substring(start, end);
    start = end + 1;
    line.trim();
    if (!line.length() || line.startsWith("#")) continue;
    totp::OtpAuth p;
    std::string err;
    if (!totp::parseOtpAuth(line.c_str(), p, err)) {
      invalid++;
      continue;
    }
    bool dup = false;
    for (const Account &a : next) dup |= a.secret == p.secret.c_str();
    if (dup) {
      duplicate++;
    } else if (next.size() >= MAX_ACCOUNTS) {
      overLimit++;
    } else {
      next.push_back({p.issuer.c_str(), p.label.c_str(), p.secret.c_str(), (uint8_t)p.digits, (uint8_t)p.period});
      added++;
    }
  }
  if (replace && added == 0) {
    flash = "Nothing restored: no valid entries, so the existing accounts were kept";
    return redirectHome();
  }
  std::vector<Account> previous = accounts;
  accounts = next;
  if (!saveAccounts()) {
    accounts = previous;
    flash = "Restore failed: could not write to flash";
    return redirectHome();
  }
  flash = String(replace ? "Replaced with " : "Restored ") + added + " account(s)";
  if (duplicate) flash += ", " + String(duplicate) + " already present";
  if (invalid) flash += ", " + String(invalid) + " invalid line(s) skipped";
  if (overLimit) flash += ", " + String(overLimit) + " over the " + MAX_ACCOUNTS + "-account limit";
  Serial.printf("[setup] restore: +%d dup %d bad %d over %d\n", added, duplicate, invalid, overLimit);
  redirectHome();
}

// Setting or resetting the password needs the PIN shown on the badge: proof of physical presence.
void handleSetPassword() {
  touchSetup();
  if (server.method() == HTTP_POST) {
    if (!checkPin()) {
      // flash already set
    } else if (server.arg("pw").length() < 8) {
      flash = "Password must be at least 8 characters";
    } else if (server.arg("pw") != server.arg("pw2")) {
      flash = "Passwords do not match";
    } else {
      MD5Builder md5;
      md5.begin();
      md5.add(String(ADMIN_USER) + ":" + REALM + ":" + server.arg("pw"));
      md5.calculate();
      writeSmallFile("/admin", md5.toString());
      rotatePin();
      flash = "Password set. Log in as 'admin'.";
      Serial.println("[setup] admin password set");
      return redirectHome();
    }
  }
  sendPage("<h2>Set admin password</h2><form method=post action=/setpw>"
           "<label>PIN shown on the badge<input type=text name=pin inputmode=numeric autocomplete=off></label>"
           "<label>New password (8+ characters)<input type=password name=pw></label>"
           "<label>Repeat<input type=password name=pw2></label><button>Set password</button></form>");
}

void handleTimezone() {
  if (!requireAuth() || !checkCsrf()) return;
  String tz = server.arg("tz");
  tz.trim();
  bool ok = tz.length() >= 3 && tz.length() <= 63;
  for (char c : tz) ok &= c > ' ' && c < 127 && c != '<' && c != '>' && c != '"';
  if (!ok) {
    flash = "Timezone not saved: expected a POSIX TZ string such as UTC0";
  } else {
    writeSmallFile("/tz", tz);
    setenv("TZ", tz.c_str(), 1);
    tzset();
    flash = "Timezone set to " + tz;
  }
  redirectHome();
}

void handleDone() {
  if (!requireAuth() || !checkCsrf()) return;
  server.send(200, "text/html", "<p>Done. The badge is going to sleep.</p>");
  delay(200);
  goToSleep("Setup finished.");
}

void handleWifiForget() {
  if (!requireAuth() || !checkCsrf()) return;
  server.send(200, "text/html", "<p>WiFi forgotten. The badge will reboot into the WiFi portal.</p>");
  delay(200);
  WiFiManager wm;
  wm.resetSettings();
  ESP.restart();
}

void runSetup() {
  Serial.println("[setup] entering setup mode");
  String apPass = randomDigits(8);
  WiFiManager wm;
  wm.setConfigPortalTimeout(300);
  wm.setHostname(HOSTNAME);
  wm.setAPCallback([apPass](WiFiManager *) {
    Serial.println("[setup] WiFi portal up");
    showMessage("WIFI SETUP", String("Join WiFi: ") + AP_NAME, "Password: " + apPass,
                "Then pick the company network", "in the page that opens.");
  });
  showMessage("SETUP MODE", "Connecting to WiFi...");
  if (!wm.autoConnect(AP_NAME, apPass.c_str())) goToSleep("WiFi setup timed out.");

  Serial.printf("[setup] joined %s as %s\n", WiFi.SSID().c_str(), WiFi.localIP().toString().c_str());
  configTime(tzInfo().c_str(), "time.google.com", "pool.ntp.org", "time.cloudflare.com");  // dates the backup file
  sessionPin = randomDigits(6);
  csrfToken = randomHex(16);
  MDNS.begin(HOSTNAME);
  server.on("/", HTTP_GET, handleRoot);
  server.on("/add", HTTP_POST, handleAdd);
  server.on("/del", HTTP_POST, handleDelete);
  server.on("/backup", HTTP_POST, handleBackup);
  server.on("/restore", HTTP_POST, handleRestore);
  server.on("/setpw", handleSetPassword);
  server.on("/tz", HTTP_POST, handleTimezone);
  server.on("/done", HTTP_POST, handleDone);
  server.on("/wifi-forget", HTTP_POST, handleWifiForget);
  server.onNotFound([] { server.send(404, "text/plain", "Not found"); });
  server.begin();
  showSetupScreen();
  touchSetup();
  for (;;) {
    server.handleClient();
    MDNS.update();
    if (millis() - setupLastActivity > SETUP_IDLE_MS) goToSleep("Setup timed out.");
    delay(2);
  }
}

// ---- Normal mode ----------------------------------------------------------------------------

uint8_t lastReading = 0xff, stableReading = 0xff;
uint32_t lastChange = 0;

// Returns a bitmask of buttons that went down since the last call (50 ms debounce).
uint8_t pollButtons() {
  uint8_t reading = 0;
  for (int i = 0; i < BTN_COUNT; i++) {
    // GPIO3 is UART RX in normal mode; bridge traffic on it must not read as left presses.
    if (i == BTN_LEFT || digitalRead(BUTTON_PINS[i]) == HIGH) reading |= 1 << i;
  }
  if (reading != lastReading) {
    lastChange = millis();
    lastReading = reading;
  }
  uint8_t pressed = 0;
  if (millis() - lastChange > 50 && reading != stableReading) {
    pressed = stableReading & ~reading;  // was high (released), now low (pressed)
    stableReading = reading;
  }
  return pressed;
}

void setup() {
  Serial.begin(115200);
  pinMode(BUTTON_PINS[BTN_CENTRE], INPUT_PULLUP);
  delay(30);
  bool setupRequested = digitalRead(BUTTON_PINS[BTN_CENTRE]) == LOW;
  Serial.printf("\n[boot] BadgyTOTP, reset: %s, centre held: %d\n", ESP.getResetReason().c_str(), setupRequested);

  display.init();
  if (!LittleFS.begin()) {
    Serial.println("[boot] LittleFS mount failed, formatting");
    LittleFS.format();
    LittleFS.begin();
  }
  loadAccounts();
  savedSelected = selected = readSmallFile("/selected").toInt();
  if (selected >= accounts.size()) selected = 0;
  Serial.printf("[boot] %u account(s), saved WiFi: '%s'\n", accounts.size(), WiFi.SSID().c_str());

  if (setupRequested || WiFi.SSID().length() == 0) runSetup();  // never returns

  if (accounts.empty()) {
    showMessage("No accounts", "Hold the centre button while", "switching on to enter setup.");
    delay(30000);
    goToSleep("No accounts configured.");
  }

  showMessage("BadgyTOTP", "Connecting to " + WiFi.SSID() + "...");
  WiFi.mode(WIFI_STA);
  WiFi.begin();
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < WIFI_TIMEOUT_MS) delay(100);
  if (WiFi.status() != WL_CONNECTED) {
    Serial.printf("[wifi] could not join '%s' (status %d)\n", WiFi.SSID().c_str(), WiFi.status());
    showMessage("No WiFi", "Could not join " + WiFi.SSID() + ".", "No codes without the time.",
                "Hold centre at power-on", "to change WiFi.");
    delay(30000);
    goToSleep("WiFi unavailable.");
  }
  Serial.printf("[wifi] joined in %lu ms, IP %s\n", millis() - start, WiFi.localIP().toString().c_str());

  timeSynced = syncTime();
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  WiFi.forceSleepBegin();
  Serial.println("[wifi] off");

  if (!timeSynced) {
    showMessage("No time sync", "NTP and HTTP both failed.", "Codes would be wrong, so", "none are shown.");
    delay(30000);
    goToSleep("Time sync failed.");
  }

  time_t now = time(nullptr);
  Serial.printf("[boot] time %ld, arming buttons, serial to receive-only\n", (long)now);
  Serial.flush();
  Serial.end();
  for (int i = 0; i < BTN_COUNT; i++)
    if (i != BTN_LEFT) pinMode(BUTTON_PINS[i], INPUT_PULLUP);
  serialListen();

  drawCodeScreen(now);
  display.update();
}

void loop() {
  static uint32_t lastInput = millis();
  static time_t lastDrawn = 0;
  static bool dirty = false;
  static bool bridgeWas = false;

  pollBridge();
  if (bridgePresent() != bridgeWas) {  // show or hide the "right: type" hint
    bridgeWas = !bridgeWas;
    dirty = true;
  }

  uint8_t pressed = pollButtons();
  if (pressed) {
    lastInput = millis();
    size_t n = accounts.size();
    if (pressed & (1 << BTN_DOWN)) selected = (selected + 1) % n;
    if (pressed & (1 << BTN_UP)) selected = (selected + n - 1) % n;
    if (pressed & (1 << BTN_RIGHT)) sendCodeToPc();
    dirty = true;
    if (pressed & (1 << BTN_CENTRE)) {  // full refresh clears partial-update ghosting
      drawCodeScreen(time(nullptr));
      display.update();
      lastDrawn = time(nullptr);
      dirty = false;
    }
  }

  time_t now = time(nullptr);
  const Account &a = accounts[selected];
  int remaining = a.period - (int)(now % a.period);
  bool newPeriod = now / a.period != lastDrawn / a.period;
  bool tick = now != lastDrawn && (remaining <= 7 || now - lastDrawn >= 2);
  if (dirty || newPeriod || tick) {
    drawCodeScreen(now);
    display.updateWindow(0, 0, display.width(), display.height(), true);
    lastDrawn = now;
    dirty = false;
  }

  if (millis() - lastInput > IDLE_SLEEP_MS) goToSleep("Idle for 2 minutes.");
  delay(10);
}
