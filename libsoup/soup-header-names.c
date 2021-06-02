/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: gperf -k '*' -D -n -s 2  */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif


/* This file has been generated with generate-header-names.py script, do not edit */
#include "soup-header-names.h"
#include <string.h>

static const char * const soup_headr_name_strings[] = {
  "Accept",
  "Accept-Charset",
  "Accept-Encoding",
  "Accept-Language",
  "Accept-Ranges",
  "Access-Control-Allow-Credentials",
  "Access-Control-Allow-Headers",
  "Access-Control-Allow-Methods",
  "Access-Control-Allow-Origin",
  "Access-Control-Expose-Headers",
  "Access-Control-Max-Age",
  "Access-Control-Request-Headers",
  "Access-Control-Request-Method",
  "Age",
  "Authentication-Info",
  "Authorization",
  "Cache-Control",
  "Connection",
  "Content-Disposition",
  "Content-Encoding",
  "Content-Language",
  "Content-Length",
  "Content-Location",
  "Content-Range",
  "Content-Security-Policy",
  "Content-Security-Policy-Report-Only",
  "Content-Type",
  "Cookie",
  "Cookie2",
  "Cross-Origin-Resource-Policy",
  "DNT",
  "Date",
  "Default-Style",
  "ETag",
  "Expect",
  "Expires",
  "Host",
  "If-Match",
  "If-Modified-Since",
  "If-None-Match",
  "If-Range",
  "If-Unmodified-Since",
  "Keep-Alive",
  "Last-Event-ID",
  "Last-Modified",
  "Link",
  "Location",
  "Origin",
  "Ping-From",
  "Ping-To",
  "Pragma",
  "Proxy-Authenticate",
  "Proxy-Authentication-Info",
  "Proxy-Authorization",
  "Purpose",
  "Range",
  "Referer",
  "Referrer-Policy",
  "Refresh",
  "Sec-WebSocket-Accept",
  "Sec-WebSocket-Extensions",
  "Sec-WebSocket-Key",
  "Sec-WebSocket-Protocol",
  "Sec-WebSocket-Version",
  "Server",
  "Server-Timing",
  "Service-Worker",
  "Service-Worker-Allowed",
  "Set-Cookie",
  "Set-Cookie2",
  "SourceMap",
  "TE",
  "Timing-Allow-Origin",
  "Trailer",
  "Transfer-Encoding",
  "Upgrade",
  "Upgrade-Insecure-Requests",
  "User-Agent",
  "Vary",
  "Via",
  "WWW-Authenticate",
  "X-Content-Type-Options",
  "X-DNS-Prefetch-Control",
  "X-Frame-Options",
  "X-SourceMap",
  "X-Temp-Tablet",
  "X-XSS-Protection",
};
struct SoupHeaderHashEntry {
    int name;
    SoupHeaderName header_name;
};

#define TOTAL_KEYWORDS 87
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 35
#define MIN_HASH_VALUE 5
#define MAX_HASH_VALUE 690
/* maximum key range = 686, duplicates = 0 */

#ifndef GPERF_DOWNCASE
#define GPERF_DOWNCASE 1
static unsigned char gperf_downcase[256] =
  {
      0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,
     30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,
     45,  46,  47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,
     60,  61,  62,  63,  64,  97,  98,  99, 100, 101, 102, 103, 104, 105, 106,
    107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
    122,  91,  92,  93,  94,  95,  96,  97,  98,  99, 100, 101, 102, 103, 104,
    105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
    135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164,
    165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,
    180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
    195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
    210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    255
  };
#endif

#ifndef GPERF_CASE_STRNCMP
#define GPERF_CASE_STRNCMP 1
static int
gperf_case_strncmp (register const char *s1, register const char *s2, register size_t n)
{
  for (; n > 0;)
    {
      unsigned char c1 = gperf_downcase[(unsigned char)*s1++];
      unsigned char c2 = gperf_downcase[(unsigned char)*s2++];
      if (c1 != 0 && c1 == c2)
        {
          n--;
          continue;
        }
      return (int)c1 - (int)c2;
    }
  return 0;
}
#endif

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
soup_header_name_hash_function (register const char *str, register size_t len)
{
  static const unsigned short asso_values[] =
    {
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691,   5, 691, 691, 691, 691,
       40, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691,   0,   5,   0,  45,   0,
       95,  10,  65,   5, 691, 210,  20,  75,   5,   0,
       60, 130,   5,  10,   5,  75,   4, 155, 165,  75,
       35, 691, 691, 691, 691, 691, 691,   0,   5,   0,
       45,   0,  95,  10,  65,   5, 691, 210,  20,  75,
        5,   0,  60, 130,   5,  10,   5,  75,   4, 155,
      165,  75,  35, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691, 691, 691, 691, 691,
      691, 691, 691, 691, 691, 691
    };
  register unsigned int hval = 0;

  switch (len)
    {
      default:
        hval += asso_values[(unsigned char)str[34]];
      /*FALLTHROUGH*/
      case 34:
        hval += asso_values[(unsigned char)str[33]];
      /*FALLTHROUGH*/
      case 33:
        hval += asso_values[(unsigned char)str[32]];
      /*FALLTHROUGH*/
      case 32:
        hval += asso_values[(unsigned char)str[31]];
      /*FALLTHROUGH*/
      case 31:
        hval += asso_values[(unsigned char)str[30]];
      /*FALLTHROUGH*/
      case 30:
        hval += asso_values[(unsigned char)str[29]];
      /*FALLTHROUGH*/
      case 29:
        hval += asso_values[(unsigned char)str[28]];
      /*FALLTHROUGH*/
      case 28:
        hval += asso_values[(unsigned char)str[27]];
      /*FALLTHROUGH*/
      case 27:
        hval += asso_values[(unsigned char)str[26]];
      /*FALLTHROUGH*/
      case 26:
        hval += asso_values[(unsigned char)str[25]];
      /*FALLTHROUGH*/
      case 25:
        hval += asso_values[(unsigned char)str[24]];
      /*FALLTHROUGH*/
      case 24:
        hval += asso_values[(unsigned char)str[23]];
      /*FALLTHROUGH*/
      case 23:
        hval += asso_values[(unsigned char)str[22]];
      /*FALLTHROUGH*/
      case 22:
        hval += asso_values[(unsigned char)str[21]];
      /*FALLTHROUGH*/
      case 21:
        hval += asso_values[(unsigned char)str[20]];
      /*FALLTHROUGH*/
      case 20:
        hval += asso_values[(unsigned char)str[19]];
      /*FALLTHROUGH*/
      case 19:
        hval += asso_values[(unsigned char)str[18]];
      /*FALLTHROUGH*/
      case 18:
        hval += asso_values[(unsigned char)str[17]];
      /*FALLTHROUGH*/
      case 17:
        hval += asso_values[(unsigned char)str[16]];
      /*FALLTHROUGH*/
      case 16:
        hval += asso_values[(unsigned char)str[15]];
      /*FALLTHROUGH*/
      case 15:
        hval += asso_values[(unsigned char)str[14]];
      /*FALLTHROUGH*/
      case 14:
        hval += asso_values[(unsigned char)str[13]];
      /*FALLTHROUGH*/
      case 13:
        hval += asso_values[(unsigned char)str[12]];
      /*FALLTHROUGH*/
      case 12:
        hval += asso_values[(unsigned char)str[11]];
      /*FALLTHROUGH*/
      case 11:
        hval += asso_values[(unsigned char)str[10]];
      /*FALLTHROUGH*/
      case 10:
        hval += asso_values[(unsigned char)str[9]];
      /*FALLTHROUGH*/
      case 9:
        hval += asso_values[(unsigned char)str[8]];
      /*FALLTHROUGH*/
      case 8:
        hval += asso_values[(unsigned char)str[7]];
      /*FALLTHROUGH*/
      case 7:
        hval += asso_values[(unsigned char)str[6]];
      /*FALLTHROUGH*/
      case 6:
        hval += asso_values[(unsigned char)str[5]];
      /*FALLTHROUGH*/
      case 5:
        hval += asso_values[(unsigned char)str[4]];
      /*FALLTHROUGH*/
      case 4:
        hval += asso_values[(unsigned char)str[3]];
      /*FALLTHROUGH*/
      case 3:
        hval += asso_values[(unsigned char)str[2]];
      /*FALLTHROUGH*/
      case 2:
        hval += asso_values[(unsigned char)str[1]];
      /*FALLTHROUGH*/
      case 1:
        hval += asso_values[(unsigned char)str[0]];
        break;
    }
  return hval;
}

struct stringpool_t
  {
    char stringpool_str0[sizeof("TE")];
    char stringpool_str1[sizeof("Via")];
    char stringpool_str2[sizeof("Age")];
    char stringpool_str3[sizeof("ETag")];
    char stringpool_str4[sizeof("Range")];
    char stringpool_str5[sizeof("Server")];
    char stringpool_str6[sizeof("Connection")];
    char stringpool_str7[sizeof("Origin")];
    char stringpool_str8[sizeof("Location")];
    char stringpool_str9[sizeof("Trailer")];
    char stringpool_str10[sizeof("Content-Range")];
    char stringpool_str11[sizeof("Date")];
    char stringpool_str12[sizeof("DNT")];
    char stringpool_str13[sizeof("Content-Location")];
    char stringpool_str14[sizeof("Accept")];
    char stringpool_str15[sizeof("Host")];
    char stringpool_str16[sizeof("Vary")];
    char stringpool_str17[sizeof("Ping-To")];
    char stringpool_str18[sizeof("Content-Encoding")];
    char stringpool_str19[sizeof("Accept-Ranges")];
    char stringpool_str20[sizeof("Cache-Control")];
    char stringpool_str21[sizeof("Last-Event-ID")];
    char stringpool_str22[sizeof("Referer")];
    char stringpool_str23[sizeof("User-Agent")];
    char stringpool_str24[sizeof("If-Range")];
    char stringpool_str25[sizeof("Content-Length")];
    char stringpool_str26[sizeof("Server-Timing")];
    char stringpool_str27[sizeof("Accept-Encoding")];
    char stringpool_str28[sizeof("Content-Language")];
    char stringpool_str29[sizeof("Pragma")];
    char stringpool_str30[sizeof("Accept-Charset")];
    char stringpool_str31[sizeof("Content-Type")];
    char stringpool_str32[sizeof("Content-Disposition")];
    char stringpool_str33[sizeof("Refresh")];
    char stringpool_str34[sizeof("Accept-Language")];
    char stringpool_str35[sizeof("Upgrade")];
    char stringpool_str36[sizeof("Transfer-Encoding")];
    char stringpool_str37[sizeof("Authorization")];
    char stringpool_str38[sizeof("Purpose")];
    char stringpool_str39[sizeof("Cookie")];
    char stringpool_str40[sizeof("SourceMap")];
    char stringpool_str41[sizeof("Expect")];
    char stringpool_str42[sizeof("Set-Cookie")];
    char stringpool_str43[sizeof("Link")];
    char stringpool_str44[sizeof("Expires")];
    char stringpool_str45[sizeof("If-Match")];
    char stringpool_str46[sizeof("Cookie2")];
    char stringpool_str47[sizeof("Ping-From")];
    char stringpool_str48[sizeof("If-None-Match")];
    char stringpool_str49[sizeof("Set-Cookie2")];
    char stringpool_str50[sizeof("Referrer-Policy")];
    char stringpool_str51[sizeof("Authentication-Info")];
    char stringpool_str52[sizeof("Access-Control-Allow-Origin")];
    char stringpool_str53[sizeof("Keep-Alive")];
    char stringpool_str54[sizeof("Last-Modified")];
    char stringpool_str55[sizeof("Access-Control-Max-Age")];
    char stringpool_str56[sizeof("Cross-Origin-Resource-Policy")];
    char stringpool_str57[sizeof("Timing-Allow-Origin")];
    char stringpool_str58[sizeof("X-Temp-Tablet")];
    char stringpool_str59[sizeof("Default-Style")];
    char stringpool_str60[sizeof("Access-Control-Allow-Credentials")];
    char stringpool_str61[sizeof("Content-Security-Policy")];
    char stringpool_str62[sizeof("Access-Control-Allow-Headers")];
    char stringpool_str63[sizeof("X-SourceMap")];
    char stringpool_str64[sizeof("If-Modified-Since")];
    char stringpool_str65[sizeof("Service-Worker")];
    char stringpool_str66[sizeof("Access-Control-Request-Headers")];
    char stringpool_str67[sizeof("X-Content-Type-Options")];
    char stringpool_str68[sizeof("Access-Control-Expose-Headers")];
    char stringpool_str69[sizeof("Sec-WebSocket-Version")];
    char stringpool_str70[sizeof("X-Frame-Options")];
    char stringpool_str71[sizeof("X-XSS-Protection")];
    char stringpool_str72[sizeof("Access-Control-Allow-Methods")];
    char stringpool_str73[sizeof("Sec-WebSocket-Accept")];
    char stringpool_str74[sizeof("Proxy-Authenticate")];
    char stringpool_str75[sizeof("If-Unmodified-Since")];
    char stringpool_str76[sizeof("Access-Control-Request-Method")];
    char stringpool_str77[sizeof("Sec-WebSocket-Protocol")];
    char stringpool_str78[sizeof("X-DNS-Prefetch-Control")];
    char stringpool_str79[sizeof("Proxy-Authorization")];
    char stringpool_str80[sizeof("Upgrade-Insecure-Requests")];
    char stringpool_str81[sizeof("Content-Security-Policy-Report-Only")];
    char stringpool_str82[sizeof("Proxy-Authentication-Info")];
    char stringpool_str83[sizeof("Sec-WebSocket-Extensions")];
    char stringpool_str84[sizeof("WWW-Authenticate")];
    char stringpool_str85[sizeof("Service-Worker-Allowed")];
    char stringpool_str86[sizeof("Sec-WebSocket-Key")];
  };
static const struct stringpool_t stringpool_contents =
  {
    "TE",
    "Via",
    "Age",
    "ETag",
    "Range",
    "Server",
    "Connection",
    "Origin",
    "Location",
    "Trailer",
    "Content-Range",
    "Date",
    "DNT",
    "Content-Location",
    "Accept",
    "Host",
    "Vary",
    "Ping-To",
    "Content-Encoding",
    "Accept-Ranges",
    "Cache-Control",
    "Last-Event-ID",
    "Referer",
    "User-Agent",
    "If-Range",
    "Content-Length",
    "Server-Timing",
    "Accept-Encoding",
    "Content-Language",
    "Pragma",
    "Accept-Charset",
    "Content-Type",
    "Content-Disposition",
    "Refresh",
    "Accept-Language",
    "Upgrade",
    "Transfer-Encoding",
    "Authorization",
    "Purpose",
    "Cookie",
    "SourceMap",
    "Expect",
    "Set-Cookie",
    "Link",
    "Expires",
    "If-Match",
    "Cookie2",
    "Ping-From",
    "If-None-Match",
    "Set-Cookie2",
    "Referrer-Policy",
    "Authentication-Info",
    "Access-Control-Allow-Origin",
    "Keep-Alive",
    "Last-Modified",
    "Access-Control-Max-Age",
    "Cross-Origin-Resource-Policy",
    "Timing-Allow-Origin",
    "X-Temp-Tablet",
    "Default-Style",
    "Access-Control-Allow-Credentials",
    "Content-Security-Policy",
    "Access-Control-Allow-Headers",
    "X-SourceMap",
    "If-Modified-Since",
    "Service-Worker",
    "Access-Control-Request-Headers",
    "X-Content-Type-Options",
    "Access-Control-Expose-Headers",
    "Sec-WebSocket-Version",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Access-Control-Allow-Methods",
    "Sec-WebSocket-Accept",
    "Proxy-Authenticate",
    "If-Unmodified-Since",
    "Access-Control-Request-Method",
    "Sec-WebSocket-Protocol",
    "X-DNS-Prefetch-Control",
    "Proxy-Authorization",
    "Upgrade-Insecure-Requests",
    "Content-Security-Policy-Report-Only",
    "Proxy-Authentication-Info",
    "Sec-WebSocket-Extensions",
    "WWW-Authenticate",
    "Service-Worker-Allowed",
    "Sec-WebSocket-Key"
  };
#define stringpool ((const char *) &stringpool_contents)

static const struct SoupHeaderHashEntry wordlist[] =
  {
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str0, SOUP_HEADER_TE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str1, SOUP_HEADER_VIA},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str2, SOUP_HEADER_AGE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str3, SOUP_HEADER_ETAG},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str4, SOUP_HEADER_RANGE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str5, SOUP_HEADER_SERVER},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str6, SOUP_HEADER_CONNECTION},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str7, SOUP_HEADER_ORIGIN},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str8, SOUP_HEADER_LOCATION},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str9, SOUP_HEADER_TRAILER},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str10, SOUP_HEADER_CONTENT_RANGE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str11, SOUP_HEADER_DATE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str12, SOUP_HEADER_DNT},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str13, SOUP_HEADER_CONTENT_LOCATION},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str14, SOUP_HEADER_ACCEPT},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str15, SOUP_HEADER_HOST},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str16, SOUP_HEADER_VARY},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str17, SOUP_HEADER_PING_TO},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str18, SOUP_HEADER_CONTENT_ENCODING},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str19, SOUP_HEADER_ACCEPT_RANGES},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str20, SOUP_HEADER_CACHE_CONTROL},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str21, SOUP_HEADER_LAST_EVENT_ID},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str22, SOUP_HEADER_REFERER},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str23, SOUP_HEADER_USER_AGENT},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str24, SOUP_HEADER_IF_RANGE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str25, SOUP_HEADER_CONTENT_LENGTH},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str26, SOUP_HEADER_SERVER_TIMING},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str27, SOUP_HEADER_ACCEPT_ENCODING},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str28, SOUP_HEADER_CONTENT_LANGUAGE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str29, SOUP_HEADER_PRAGMA},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str30, SOUP_HEADER_ACCEPT_CHARSET},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str31, SOUP_HEADER_CONTENT_TYPE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str32, SOUP_HEADER_CONTENT_DISPOSITION},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str33, SOUP_HEADER_REFRESH},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str34, SOUP_HEADER_ACCEPT_LANGUAGE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str35, SOUP_HEADER_UPGRADE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str36, SOUP_HEADER_TRANSFER_ENCODING},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str37, SOUP_HEADER_AUTHORIZATION},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str38, SOUP_HEADER_PURPOSE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str39, SOUP_HEADER_COOKIE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str40, SOUP_HEADER_SOURCEMAP},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str41, SOUP_HEADER_EXPECT},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str42, SOUP_HEADER_SET_COOKIE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str43, SOUP_HEADER_LINK},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str44, SOUP_HEADER_EXPIRES},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str45, SOUP_HEADER_IF_MATCH},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str46, SOUP_HEADER_COOKIE2},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str47, SOUP_HEADER_PING_FROM},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str48, SOUP_HEADER_IF_NONE_MATCH},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str49, SOUP_HEADER_SET_COOKIE2},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str50, SOUP_HEADER_REFERRER_POLICY},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str51, SOUP_HEADER_AUTHENTICATION_INFO},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str52, SOUP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str53, SOUP_HEADER_KEEP_ALIVE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str54, SOUP_HEADER_LAST_MODIFIED},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str55, SOUP_HEADER_ACCESS_CONTROL_MAX_AGE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str56, SOUP_HEADER_CROSS_ORIGIN_RESOURCE_POLICY},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str57, SOUP_HEADER_TIMING_ALLOW_ORIGIN},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str58, SOUP_HEADER_X_TEMP_TABLET},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str59, SOUP_HEADER_DEFAULT_STYLE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str60, SOUP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str61, SOUP_HEADER_CONTENT_SECURITY_POLICY},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str62, SOUP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str63, SOUP_HEADER_X_SOURCEMAP},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str64, SOUP_HEADER_IF_MODIFIED_SINCE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str65, SOUP_HEADER_SERVICE_WORKER},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str66, SOUP_HEADER_ACCESS_CONTROL_REQUEST_HEADERS},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str67, SOUP_HEADER_X_CONTENT_TYPE_OPTIONS},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str68, SOUP_HEADER_ACCESS_CONTROL_EXPOSE_HEADERS},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str69, SOUP_HEADER_SEC_WEBSOCKET_VERSION},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str70, SOUP_HEADER_X_FRAME_OPTIONS},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str71, SOUP_HEADER_X_XSS_PROTECTION},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str72, SOUP_HEADER_ACCESS_CONTROL_ALLOW_METHODS},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str73, SOUP_HEADER_SEC_WEBSOCKET_ACCEPT},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str74, SOUP_HEADER_PROXY_AUTHENTICATE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str75, SOUP_HEADER_IF_UNMODIFIED_SINCE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str76, SOUP_HEADER_ACCESS_CONTROL_REQUEST_METHOD},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str77, SOUP_HEADER_SEC_WEBSOCKET_PROTOCOL},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str78, SOUP_HEADER_X_DNS_PREFETCH_CONTROL},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str79, SOUP_HEADER_PROXY_AUTHORIZATION},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str80, SOUP_HEADER_UPGRADE_INSECURE_REQUESTS},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str81, SOUP_HEADER_CONTENT_SECURITY_POLICY_REPORT_ONLY},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str82, SOUP_HEADER_PROXY_AUTHENTICATION_INFO},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str83, SOUP_HEADER_SEC_WEBSOCKET_EXTENSIONS},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str84, SOUP_HEADER_WWW_AUTHENTICATE},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str85, SOUP_HEADER_SERVICE_WORKER_ALLOWED},
    {(int)(size_t)&((struct stringpool_t *)0)->stringpool_str86, SOUP_HEADER_SEC_WEBSOCKET_KEY}
  };

static const signed char lookup[] =
  {
    -1, -1, -1, -1, -1,  0, -1, -1, -1,  1,  2, -1, -1, -1,
    -1,  3, -1, -1, -1, -1,  4, -1, -1, -1,  5,  6, -1, -1,
    -1, -1,  7, -1, -1, -1, -1,  8, -1, -1, -1, -1,  9, -1,
    -1, -1, -1, 10, -1, -1, -1, -1, 11, -1, -1, -1, -1, 12,
    -1, -1, -1, -1, 13, -1, -1, -1, -1, 14, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, -1, -1,
    16, -1, -1, -1, -1, -1, 17, -1, -1, -1, -1, 18, -1, -1,
    -1, -1, 19, -1, -1, -1, -1, 20, -1, -1, -1, 21, 22, -1,
    -1, -1, -1, 23, -1, -1, -1, -1, -1, -1, -1, -1, -1, 24,
    -1, -1, -1, -1, 25, -1, -1, -1, 26, -1, -1, -1, -1, -1,
    27, -1, -1, -1, -1, 28, -1, -1, -1, -1, 29, -1, -1, -1,
    -1, 30, -1, -1, -1, -1, -1, -1, -1, -1, -1, 31, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, 32, -1, -1, -1, -1, 33, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, 34, -1, -1, -1, -1, 35,
    -1, -1, -1, -1, 36, -1, -1, -1, -1, 37, -1, -1, -1, -1,
    38, -1, -1, -1, -1, 39, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 40, -1, -1, -1, -1, 41, -1, -1, -1, -1, 42, -1, -1,
    -1, -1, 43, -1, -1, -1, -1, 44, -1, -1, -1, -1, 45, -1,
    -1, -1, -1, 46, -1, -1, -1, -1, 47, -1, -1, -1, -1, 48,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 49, -1, -1, -1, -1,
    50, -1, -1, -1, -1, 51, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 52, -1, -1, -1, -1, -1, -1, -1, -1, 53, -1, -1, -1,
    -1, -1, 54, -1, -1, -1, -1, -1, -1, -1, -1, -1, 55, -1,
    -1, -1, -1, 56, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, 57, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    58, -1, -1, -1, -1, 59, -1, -1, -1, -1, 60, -1, -1, -1,
    -1, 61, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1,
    -1, -1, -1, 63, -1, -1, -1, -1, 64, -1, -1, -1, 65, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    66, -1, -1, -1, -1, 67, -1, -1, -1, -1, 68, -1, -1, -1,
    69, 70, -1, -1, -1, -1, -1, -1, -1, -1, -1, 71, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, 72, -1, -1, -1, -1, 73, -1, -1, -1, -1, 74,
    -1, -1, -1, -1, 75, -1, -1, -1, -1, 76, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, 77, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 78, -1, -1, -1, -1, -1, -1, -1, -1, -1, 79, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, 80, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, 81, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, 82, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, 83, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, 84, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, 85, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, 86
  };

static const struct SoupHeaderHashEntry *
soup_header_name_find (register const char *str, register size_t len)
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = soup_header_name_hash_function (str, len);

      if (key <= MAX_HASH_VALUE)
        {
          register int index = lookup[key];

          if (index >= 0)
            {
              register const char *s = wordlist[index].name + stringpool;

              if ((((unsigned char)*str ^ (unsigned char)*s) & ~32) == 0 && !gperf_case_strncmp (str, s, len) && s[len] == '\0')
                return &wordlist[index];
            }
        }
    }
  return 0;
}

SoupHeaderName soup_header_name_from_string (const char *str)
{
        const struct SoupHeaderHashEntry *entry;

        entry = soup_header_name_find (str, strlen (str));
        return entry ? entry->header_name : SOUP_HEADER_UNKNOWN;
}

const char *soup_header_name_to_string (SoupHeaderName name)
{
        if (name == SOUP_HEADER_UNKNOWN)
                return NULL;

        return soup_headr_name_strings[name];
}
