#include "cshake128.h"
#include <string.h>

// ---------------------------------------------------------------------------
// Keccak-f[1600] — self-contained, no external dependencies
// ---------------------------------------------------------------------------

#define ROUNDS    24
#define RATE      168   // bytes — cSHAKE128 rate = 1344 bits

#define ROT64(x, n) (((x) << (n)) | ((x) >> (64-(n))))

// Round constants (Iota step)
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rho rotation offsets and Pi lane indices (combined Rho+Pi step)
static const int ROTC[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};
static const int PILN[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

static void keccakf(uint64_t st[25]) {
    uint64_t bc[5], t;

    for (int r = 0; r < ROUNDS; r++) {
        // Theta
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i+4)%5] ^ ROT64(bc[(i+1)%5], 1);
            for (int j = 0; j < 25; j += 5) st[j+i] ^= t;
        }

        // Rho + Pi (combined into one pass)
        t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = PILN[i];
            bc[0] = st[j];
            st[j] = ROT64(t, ROTC[i]);
            t = bc[0];
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) bc[i] = st[j+i];
            for (int i = 0; i < 5; i++)
                st[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
        }

        // Iota
        st[0] ^= RC[r];
    }
}

// ---------------------------------------------------------------------------
// Sponge helpers
// ---------------------------------------------------------------------------

// XOR data into the Keccak state, applying the permutation at each block boundary
static void absorb(uint64_t st[25], const uint8_t *data, size_t len, size_t *pos) {
    for (size_t i = 0; i < len; i++) {
        ((uint8_t *)st)[*pos] ^= data[i];
        if (++(*pos) == RATE) {
            keccakf(st);
            *pos = 0;
        }
    }
}

// Absorb zero bytes up to the next block boundary (bytepad padding)
// Zero XOR leaves state unchanged, but the permutation MUST still be applied
static void absorb_zero_pad(uint64_t st[25], size_t *pos) {
    if (*pos == 0) return;  // already on a boundary
    // positions [*pos .. RATE-1] are 0 (memset'd at init) — XOR is no-op
    keccakf(st);
    *pos = 0;
}

// Apply cSHAKE domain byte (0x04), final padding, and squeeze 'outbytes' bytes
static void finalize_squeeze(uint64_t st[25], size_t pos,
                              uint8_t *out, size_t outbytes) {
    // cSHAKE domain separator = 0x04 (vs. 0x1F for plain SHAKE128)
    ((uint8_t *)st)[pos]      ^= 0x04;
    ((uint8_t *)st)[RATE - 1] ^= 0x80;
    keccakf(st);

    size_t done = 0;
    while (done < outbytes) {
        size_t take = (outbytes - done < RATE) ? (outbytes - done) : RATE;
        memcpy(out + done, st, take);
        done += take;
        if (done < outbytes) keccakf(st);
    }
}

// ---------------------------------------------------------------------------
// NIST SP 800-185 encoding helpers
// left_encode(x): [n, x_n-1, ..., x_0]  where n = byte length of x
// ---------------------------------------------------------------------------

static void absorb_left_encode(uint64_t st[25], size_t val, size_t *pos) {
    uint8_t buf[9];
    int n = 0;
    uint64_t v = (uint64_t)val;
    // find minimum byte length
    uint64_t tmp = v;
    do { n++; tmp >>= 8; } while (tmp);
    buf[0] = (uint8_t)n;
    for (int i = n; i >= 1; i--) {
        buf[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
    absorb(st, buf, (size_t)n + 1, pos);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void cshake128(const uint8_t *input,  size_t input_len,
               const uint8_t *custom, size_t custom_len,
               uint8_t       *output, size_t output_bits) {
    uint64_t st[25];
    memset(st, 0, sizeof(st));
    size_t pos = 0;

    if (custom_len == 0) {
        // cSHAKE128 with empty N and S degenerates to SHAKE128 (domain 0x1F)
        absorb(st, input, input_len, &pos);
        ((uint8_t *)st)[pos]      ^= 0x1F;
        ((uint8_t *)st)[RATE - 1] ^= 0x80;
        keccakf(st);
        memcpy(output, st, output_bits / 8);
        return;
    }

    // bytepad(encode_string("") || encode_string(S), RATE)
    // bytepad prefix = left_encode(RATE)
    absorb_left_encode(st, RATE, &pos);
    // encode_string("") = left_encode(0) || ""
    absorb_left_encode(st, 0, &pos);
    // encode_string(S) = left_encode(|S|*8) || S
    absorb_left_encode(st, custom_len * 8, &pos);
    absorb(st, custom, custom_len, &pos);
    // pad remainder of the bytepad block with zeros
    absorb_zero_pad(st, &pos);
    // pos == 0 here: the bytepad block has been absorbed and permuted

    // Absorb the actual input
    absorb(st, input, input_len, &pos);

    // Squeeze
    finalize_squeeze(st, pos, output, output_bits / 8);
}
