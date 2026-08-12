#pragma once
#include <stddef.h>
#include <stdint.h>

// cSHAKE128 per NIST SP 800-185 §3
// Used exclusively for HHIT/DET ORCHID generation — RFC 9374 §3.5.2
//
// input      : Prefix | AdditionalInfo | OGA_ID | HOST_ID  (see det_generator.cpp)
// custom     : customisation string S  — the ORCHID Context ID for DETs
// custom_len : byte length of S
// output     : destination buffer  (must hold at least output_bits/8 bytes)
// output_bits: desired output in bits  (must be a multiple of 8)
void cshake128(const uint8_t *input,  size_t input_len,
               const uint8_t *custom, size_t custom_len,
               uint8_t       *output, size_t output_bits);
