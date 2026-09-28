#include <string.h>
#include <totp.h>
#include <unity.h>

using namespace totp;

static const uint8_t RFC_KEY[] = "12345678901234567890";  // 20 bytes, RFC 4226/6238 test key

void setUp() {}
void tearDown() {}

// Independent literal: SHA1("abc") from FIPS 180-1.
void test_sha1_abc() {
  uint8_t out[20];
  sha1((const uint8_t *)"abc", 3, out);
  const uint8_t expect[20] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                              0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, out, 20);
}

// Two-block message, exercises the padding boundary (FIPS 180-1 test 2).
void test_sha1_two_block() {
  const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint8_t out[20];
  sha1((const uint8_t *)m, strlen(m), out);
  const uint8_t expect[20] = {0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
                              0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expect, out, 20);
}

// RFC 4226 Appendix D, counters 0..9, 6 digits.
void test_hotp_rfc4226() {
  const uint32_t expect[10] = {755224, 287082, 359152, 969429, 338314,
                               254676, 287922, 162583, 399871, 520489};
  for (int i = 0; i < 10; i++) TEST_ASSERT_EQUAL_UINT32(expect[i], hotp(RFC_KEY, 20, i, 6));
}

// RFC 6238 Appendix B, SHA1 column, 8 digits.
void test_totp_rfc6238() {
  const uint64_t times[6] = {59ULL, 1111111109ULL, 1111111111ULL, 1234567890ULL, 2000000000ULL, 20000000000ULL};
  const char *expect[6] = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};
  for (int i = 0; i < 6; i++) {
    TEST_ASSERT_EQUAL_STRING(expect[i], formatCode(totpAt(RFC_KEY, 20, times[i], 30, 8), 8).c_str());
  }
}

void test_base32_decode() {
  // "12345678901234567890" in base32, written the way Google shows it: lower case, spaced, no padding.
  uint8_t out[32];
  int n = base32Decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", out, sizeof(out));
  TEST_ASSERT_EQUAL_INT(20, n);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(RFC_KEY, out, 20);
  TEST_ASSERT_EQUAL_INT(-1, base32Decode("GEZD1", out, sizeof(out)));  // '1' is not base32
  TEST_ASSERT_EQUAL_INT(-1, base32Decode("GEZDGNBVGY3TQOJQ", out, 2));  // overflow
  TEST_ASSERT_EQUAL_STRING("GEZDGNBV", normaliseBase32("gezd-gnbv==").c_str());
  TEST_ASSERT_EQUAL_STRING("", normaliseBase32("abc0").c_str());
}

void test_otpauth_parse() {
  OtpAuth a;
  std::string err;
  TEST_ASSERT_TRUE(parseOtpAuth(
      "otpauth://totp/Google%3Aboardroom%40example.com?secret=gezdgnbvgy3tqojq&issuer=Google", a, err));
  TEST_ASSERT_EQUAL_STRING("Google", a.issuer.c_str());
  TEST_ASSERT_EQUAL_STRING("boardroom@example.com", a.label.c_str());
  TEST_ASSERT_EQUAL_STRING("GEZDGNBVGY3TQOJQ", a.secret.c_str());
  TEST_ASSERT_EQUAL_INT(6, a.digits);
  TEST_ASSERT_EQUAL_INT(30, a.period);

  TEST_ASSERT_TRUE(parseOtpAuth("otpauth://totp/Slack:me?secret=GEZDGNBV&digits=8&period=60", a, err));
  TEST_ASSERT_EQUAL_STRING("Slack", a.issuer.c_str());  // falls back to the label prefix
  TEST_ASSERT_EQUAL_INT(8, a.digits);
  TEST_ASSERT_EQUAL_INT(60, a.period);

  TEST_ASSERT_FALSE(parseOtpAuth("otpauth://hotp/x?secret=GEZDGNBV", a, err));
  TEST_ASSERT_FALSE(parseOtpAuth("otpauth://totp/x?secret=GEZDGNBV&algorithm=SHA256", a, err));
  TEST_ASSERT_FALSE(parseOtpAuth("otpauth://totp/x?issuer=nosecret", a, err));
  TEST_ASSERT_FALSE(parseOtpAuth("https://example.com", a, err));
}

void test_otpauth_build() {
  OtpAuth a;
  a.issuer = "Acme & Co";
  a.label = "board room@example.com";
  a.secret = "GEZDGNBVGY3TQOJQ";
  // Independent literal: what the export must look like, byte for byte.
  TEST_ASSERT_EQUAL_STRING(
      "otpauth://totp/Acme%20%26%20Co:board%20room%40example.com?secret=GEZDGNBVGY3TQOJQ"
      "&issuer=Acme%20%26%20Co&algorithm=SHA1&digits=6&period=30",
      buildOtpAuth(a).c_str());

  // Round trip, including a label with a colon in it and no issuer.
  OtpAuth b;
  b.label = "a:b";
  b.secret = "GEZDGNBV";
  b.digits = 8;
  b.period = 60;
  OtpAuth back;
  std::string err;
  TEST_ASSERT_TRUE(parseOtpAuth(buildOtpAuth(a), back, err));
  TEST_ASSERT_EQUAL_STRING(a.issuer.c_str(), back.issuer.c_str());
  TEST_ASSERT_EQUAL_STRING(a.label.c_str(), back.label.c_str());
  TEST_ASSERT_EQUAL_STRING(a.secret.c_str(), back.secret.c_str());
  TEST_ASSERT_TRUE(parseOtpAuth(buildOtpAuth(b), back, err));
  TEST_ASSERT_EQUAL_STRING("a:b", back.label.c_str());
  TEST_ASSERT_EQUAL_INT(8, back.digits);
  TEST_ASSERT_EQUAL_INT(60, back.period);
}

void test_format_code() {
  TEST_ASSERT_EQUAL_STRING("000042", formatCode(42, 6).c_str());
  TEST_ASSERT_EQUAL_STRING("000000", formatCode(0, 6).c_str());
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(test_sha1_abc);
  RUN_TEST(test_sha1_two_block);
  RUN_TEST(test_hotp_rfc4226);
  RUN_TEST(test_totp_rfc6238);
  RUN_TEST(test_base32_decode);
  RUN_TEST(test_otpauth_parse);
  RUN_TEST(test_otpauth_build);
  RUN_TEST(test_format_code);
  return UNITY_END();
}
