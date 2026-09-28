// Portable TOTP core (RFC 4226 / RFC 6238, SHA1 only). No Arduino dependencies,
// so the same code runs in the native unit tests and on the ESP8266.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string>

namespace totp {

void sha1(const uint8_t *msg, size_t len, uint8_t out[20]);
void hmacSha1(const uint8_t *key, size_t keyLen, const uint8_t *msg, size_t msgLen, uint8_t out[20]);

// Decodes RFC 4648 base32. Case-insensitive; spaces, dashes and '=' padding are ignored.
// Returns the number of bytes written, or -1 on an invalid character or overflow.
int base32Decode(const char *in, uint8_t *out, size_t outCap);

// Upper-cases and strips spaces/dashes/padding. Returns "" if the input is not valid base32.
std::string normaliseBase32(const std::string &in);

uint32_t hotp(const uint8_t *key, size_t keyLen, uint64_t counter, int digits);
uint32_t totpAt(const uint8_t *key, size_t keyLen, uint64_t unixTime, int period, int digits);

// Zero-padded code, e.g. 6 digits -> "012345".
std::string formatCode(uint32_t code, int digits);

struct OtpAuth {
  std::string issuer;
  std::string label;   // account part of the label, issuer prefix removed
  std::string secret;  // normalised base32
  int digits = 6;
  int period = 30;
};

// Parses otpauth://totp/Issuer:account?secret=...&issuer=...&digits=...&period=...
// Rejects hotp, non-SHA1 algorithms, and secrets that do not decode.
bool parseOtpAuth(const std::string &uri, OtpAuth &out, std::string &err);

// Inverse of parseOtpAuth: otpauth://totp/Issuer:label?secret=...&issuer=...&digits=...&period=...
std::string buildOtpAuth(const OtpAuth &a);

}  // namespace totp
