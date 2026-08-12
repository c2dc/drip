#include "drip_link.h"
#include "drip_auth_page.h"
#include <string.h>

// SAM Authentication Data offsets — RFC 9575 §4.2 Figure 5
#define LINK_OFF_SAMTYPE     0   // 1
#define LINK_OFF_VNB         1   // 4
#define LINK_OFF_VNA         5   // 4
#define LINK_OFF_DET_CHILD   9   // 16
#define LINK_OFF_HI_CHILD    25  // 32
#define LINK_OFF_DET_PARENT  57  // 16
#define LINK_OFF_SIG         73  // 64  -> ends at 137

void drip_link_serialize_sam(const BroadcastEndorsement *be,
                             uint8_t sam[DRIP_LINK_SAM_BYTES]) {
    memset(sam, 0, DRIP_LINK_SAM_BYTES);

    sam[LINK_OFF_SAMTYPE] = DRIP_SAM_TYPE_LINK;            // 0x01
    drip_put_le32(&sam[LINK_OFF_VNB], be->vnb);
    drip_put_le32(&sam[LINK_OFF_VNA], be->vna);
    memcpy(&sam[LINK_OFF_DET_CHILD],  be->det_child,  DET_BYTES);
    memcpy(&sam[LINK_OFF_HI_CHILD],   be->hi_child,   DRIP_BE_HI_BYTES);
    memcpy(&sam[LINK_OFF_DET_PARENT], be->det_parent, DET_BYTES);
    memcpy(&sam[LINK_OFF_SIG],        be->sig,        DRIP_BE_SIG_BYTES);
}

uint8_t drip_link_build_be(const BroadcastEndorsement *be,
                           uint8_t out[][F3411_MSG_BYTES],
                           uint8_t max_pages) {
    uint8_t sam[DRIP_LINK_SAM_BYTES];
    drip_link_serialize_sam(be, sam);

    // ASTM page-0 Timestamp header carries the BE's VNB (the validity anchor).
    return drip_auth_scatter(sam, DRIP_LINK_SAM_BYTES, be->vnb, out, max_pages);
}
