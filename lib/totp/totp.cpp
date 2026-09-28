#include "totp.h"

#include <stdlib.h>
#include <string.h>

namespace totp {

namespace {

inline uint32_t rol(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }

void sha1Block(uint32_t h[5], const uint8_t block[64]) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++) {
    w[i] = (uint32_t)block[i * 4] << 24 | (uint32_t)block[i * 4 + 1] << 16 |
           (uint32_t)block[i * 4 + 2] << 8 | block[i * 4 + 3];
  }
  for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
  for (int i = 0; i < 80; i++) {
    uint32_t f, k;
    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    uint32_t t = rol(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rol(b, 30);
    b = a;
    a = t;
  }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
}

// Streams two buffers through SHA1 so HMAC never needs to concatenate key pad + message.
void sha1Two(const uint8_t *a, size_t aLen, const uint8_t *b, size_t bLen, uint8_t out[20]) {
  uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
  uint8_t block[64];
  size_t fill = 0;
  uint64_t total = (uint64_t)(aLen + bLen);

  auto feed = [&](const uint8_t *p, size_t n) {
    while (n--) {
      block[fill++] = *p++;
      if (fill == 64) {
        sha1Block(h, block);
        fill = 0;
      }
    }
  };
  feed(a, aLen);
  feed(b, bLen);

  block[fill++] = 0x80;
  if (fill > 56) {
    while (fill < 64) block[fill++] = 0;
    sha1Block(h, block);
    fill = 0;
  }
  while (fill < 56) block[fill++] = 0;
  uint64_t bits = total * 8;
  for (int i = 7; i >= 0; i--) block[fill++] = (uint8_t)(bits >> (i * 8));
  sha1Block(h, block);

  for (int i = 0; i < 5; i++) {
    out[i * 4] = h[i] >> 24;
    out[i * 4 + 1] = h[i] >> 16;
    out[i * 4 + 2] = h[i] >> 8;
    out[i * 4 + 3] = h[i];
  }
}

int base32Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= '2' && c <= '7') return c - '2' + 26;
  return -1;
}

bool isIgnorable(char c) { return c == ' ' || c == '-' || c == '=' || c == '\t'; }

int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string urlDecode(const std::string &s) {
  std::string out;
  for (size_t i = 0; i < s.size(); i++) {
    if (s[i] == '%' && i + 2 < s.size() && hexValue(s[i + 1]) >= 0 && hexValue(s[i + 2]) >= 0) {
      out += (char)(hexValue(s[i + 1]) * 16 + hexValue(s[i + 2]));
      i += 2;
    } else if (s[i] == '+') {
      out += ' ';
    } else {
      out += s[i];
    }
  }
  return out;
}

std::string lower(std::string s) {
  for (auto &c : s)
    if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
  return s;
}

std::string trim(const std::string &s) {
  size_t a = 0, b = s.size();
  while (a < b && s[a] == ' ') a++;
  while (b > a && s[b - 1] == ' ') b--;
  return s.substr(a, b - a);
}

}  // namespace

void sha1(const uint8_t *msg, size_t len, uint8_t out[20]) { sha1Two(msg, len, nullptr, 0, out); }

void hmacSha1(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen, uint8_t out[20]) {
  uint8_t k[64] = {0};
  if (keyLen > 64) {
    sha1(key, keyLen, k);
  } else {
    memcpy(k, key, keyLen);
  }
  uint8_t pad[64];
  uint8_t inner[20];
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
  sha1Two(pad, 64, msg, msgLen, inner);
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
  sha1Two(pad, 64, inner, 20, out);
}

int base32Decode(const char *in, uint8_t *out, size_t outCap) {
  uint32_t buffer = 0;
  int bits = 0;
  size_t n = 0;
  for (const char *p = in; *p; p++) {
    if (isIgnorable(*p)) continue;
    int v = base32Value(*p);
    if (v < 0) return -1;
    buffer = (buffer << 5) | (uint32_t)v;
    bits += 5;
    if (bits >= 8) {
      if (n >= outCap) return -1;
      out[n++] = (uint8_t)(buffer >> (bits - 8));
      bits -= 8;
    }
  }
  return (int)n;
}

std::string normaliseBase32(const std::string &in) {
  std::string out;
  for (char c : in) {
    if (isIgnorable(c)) continue;
    if (base32Value(c) < 0) return "";
    out += (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
  }
  return out;
}

uint32_t hotp(const uint8_t *key, size_t keyLen, uint64_t counter, int digits) {
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) {
    msg[i] = (uint8_t)counter;
    counter >>= 8;
  }
  uint8_t mac[20];
  hmacSha1(key, keyLen, msg, 8, mac);
  int off = mac[19] & 0x0f;
  uint32_t bin = ((uint32_t)(mac[off] & 0x7f) << 24) | ((uint32_t)mac[off + 1] << 16) |
                 ((uint32_t)mac[off + 2] << 8) | mac[off + 3];
  uint32_t mod = 1;
  for (int i = 0; i < digits; i++) mod *= 10;
  return bin % mod;
}

uint32_t totpAt(const uint8_t *key, size_t keyLen, uint64_t unixTime, int period, int digits) {
  return hotp(key, keyLen, unixTime / (uint64_t)period, digits);
}

std::string formatCode(uint32_t code, int digits) {
  std::string s(digits, '0');
  for (int i = digits - 1; i >= 0 && code; i--) {
    s[i] = (char)('0' + code % 10);
    code /= 10;
  }
  return s;
}

bool parseOtpAuth(const std::string &uri, OtpAuth &out, std::string &err) {
  const std::string scheme = "otpauth://";
  if (lower(uri.substr(0, scheme.size())) != scheme) {
    err = "not an otpauth:// URI";
    return false;
  }
  std::string rest = uri.substr(scheme.size());
  size_t slash = rest.find('/');
  if (slash == std::string::npos) {
    err = "missing type";
    return false;
  }
  if (lower(rest.substr(0, slash)) != "totp") {
    err = "only totp is supported";
    return false;
  }
  rest = rest.substr(slash + 1);

  size_t q = rest.find('?');
  std::string rawLabel = rest.substr(0, q);
  std::string query = q == std::string::npos ? "" : rest.substr(q + 1);

  OtpAuth r;
  std::string labelIssuer;
  std::string secret, issuer;
  size_t pos = 0;
  while (pos <= query.size() && !query.empty()) {
    size_t amp = query.find('&', pos);
    std::string kv = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
    size_t eq = kv.find('=');
    if (eq != std::string::npos) {
      std::string k = lower(kv.substr(0, eq));
      std::string v = urlDecode(kv.substr(eq + 1));
      if (k == "secret") {
        secret = v;
      } else if (k == "issuer") {
        issuer = v;
      } else if (k == "digits") {
        r.digits = atoi(v.c_str());
      } else if (k == "period") {
        r.period = atoi(v.c_str());
      } else if (k == "algorithm" && lower(v) != "sha1") {
        err = "only SHA1 is supported";
        return false;
      }
    }
    if (amp == std::string::npos) break;
    pos = amp + 1;
  }

  // A literal ':' always separates issuer from account. An encoded one (%3A, which Google emits)
  // only does when the prefix matches the issuer parameter; otherwise it is part of the account.
  size_t colon = rawLabel.find(':');
  if (colon != std::string::npos) {
    labelIssuer = trim(urlDecode(rawLabel.substr(0, colon)));
    r.label = trim(urlDecode(rawLabel.substr(colon + 1)));
  } else {
    std::string label = urlDecode(rawLabel);
    colon = label.find(':');
    if (colon != std::string::npos && !issuer.empty() && trim(label.substr(0, colon)) == issuer) {
      labelIssuer = issuer;
      r.label = trim(label.substr(colon + 1));
    } else {
      r.label = trim(label);
    }
  }

  r.issuer = !issuer.empty() ? issuer : labelIssuer;
  r.secret = normaliseBase32(secret);
  uint8_t tmp[64];
  if (r.secret.empty() || base32Decode(r.secret.c_str(), tmp, sizeof(tmp)) <= 0) {
    err = "secret is missing or not valid base32";
    return false;
  }
  if (r.digits < 6 || r.digits > 8) {
    err = "digits must be 6-8";
    return false;
  }
  if (r.period < 10 || r.period > 120) {
    err = "period must be 10-120 s";
    return false;
  }
  out = r;
  return true;
}

std::string buildOtpAuth(const OtpAuth &a) {
  auto enc = [](const std::string &s) {
    static const char *HEX = "0123456789ABCDEF";
    std::string o;
    for (unsigned char c : s) {
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
          c == '_' || c == '~') {
        o += (char)c;
      } else {
        o += '%';
        o += HEX[c >> 4];
        o += HEX[c & 15];
      }
    }
    return o;
  };
  std::string uri = "otpauth://totp/";
  if (!a.issuer.empty()) uri += enc(a.issuer) + ":";
  uri += enc(a.label) + "?secret=" + a.secret;
  if (!a.issuer.empty()) uri += "&issuer=" + enc(a.issuer);
  uri += "&algorithm=SHA1&digits=" + std::to_string(a.digits) + "&period=" + std::to_string(a.period);
  return uri;
}

}  // namespace totp
