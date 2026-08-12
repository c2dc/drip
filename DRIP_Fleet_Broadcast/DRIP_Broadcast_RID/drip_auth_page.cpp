#include "drip_auth_page.h"
#include <string.h>

#define AUTH_PAGE0_DATA   17   // SAM data octets carried in page 0
#define AUTH_PAGEN_DATA   23   // SAM data octets per continuation page

uint8_t drip_auth_pages_needed(uint8_t auth_len) {
    if (auth_len <= AUTH_PAGE0_DATA) return 1;
    // ceil((auth_len - 17) / 23) + 1
    return (uint8_t)(1 + ((auth_len - AUTH_PAGE0_DATA + (AUTH_PAGEN_DATA - 1))
                          / AUTH_PAGEN_DATA));
}

uint8_t drip_auth_scatter(const uint8_t *auth_data, uint8_t auth_len,
                          uint32_t timestamp,
                          uint8_t out[][F3411_MSG_BYTES], uint8_t max_pages) {

    uint8_t pages = drip_auth_pages_needed(auth_len);
    if (pages > max_pages) return 0;            // caller's buffer too small

    const uint8_t last_page_index = pages - 1;  // ASTM Last Page Index (0-based)

    // Zero every page first -> guarantees null padding on the final page and
    // removes the uninitialised trailing byte (the 0xB3 from Finding 1).
    for (uint8_t p = 0; p < pages; p++) memset(out[p], 0, F3411_MSG_BYTES);

    // ---- Page 0 ----------------------------------------------------------
    out[0][0] = (F3411_TYPE_AUTH    << 4) | F3411_PROTO_VER;   // 0x22
    out[0][1] = (F3411_AUTH_TYPE_SAM << 4) | 0x0;              // 0x50: SAM, page 0
    out[0][2] = last_page_index;                               // dedicated LPI octet
    out[0][3] = auth_len;                                      // Length field
    drip_put_le32(&out[0][4], timestamp);                     // Timestamp [4..7]

    uint8_t n0 = (auth_len < AUTH_PAGE0_DATA) ? auth_len : AUTH_PAGE0_DATA;
    memcpy(&out[0][8], auth_data, n0);                        // Auth Data [8..24]

    // ---- Pages 1..N ------------------------------------------------------
    uint8_t off = n0;
    for (uint8_t p = 1; p < pages; p++) {
        out[p][0] = (F3411_TYPE_AUTH    << 4) | F3411_PROTO_VER;   // 0x22
        out[p][1] = (F3411_AUTH_TYPE_SAM << 4) | p;                // 0x51..0x5N
        uint8_t rem  = auth_len - off;
        uint8_t take = (rem < AUTH_PAGEN_DATA) ? rem : AUTH_PAGEN_DATA;
        memcpy(&out[p][2], &auth_data[off], take);                // Auth Data [2..24]
        off += take;
    }

    return pages;
}
