//
// arch/x86_64/rsp/vabs.h
//
// This file is subject to the terms and conditions defined in
// 'LICENSE', which is part of this source code package.
//

#include "common.h"

static inline __m128i rsp_vabs(__m128i vs, __m128i vt,
  __m128i zero, __m128i *acc_lo) {
  __m128i sign_lt = _mm_srai_epi16(vs, 15);
  __m128i vs_zero = _mm_cmpeq_epi16(vs, zero);
  __m128i vd;

  // Careful: if VT = 0x8000 and VS is negative,
  // acc_lo will be 0x8000 but vd will be 0x7FFF.
  vd = _mm_xor_si128(vt, sign_lt);
  *acc_lo = _mm_sub_epi16(vd, sign_lt);
  vd = _mm_subs_epi16(vd, sign_lt);
  *acc_lo = _mm_andnot_si128(vs_zero, *acc_lo);
  return _mm_andnot_si128(vs_zero, vd);
}

