/***************************************************************************//**
 * @file
 * @brief Silicon Labs PSA Crypto Secure Engine Driver PAKE functions.
 *******************************************************************************
 * # License
 * <b>Copyright 2026 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * SPDX-License-Identifier: Zlib
 *
 * The licensor of this software is Silicon Laboratories Inc.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 ******************************************************************************/

#ifndef SLI_SE_DRIVER_PAKE_H
#define SLI_SE_DRIVER_PAKE_H

/// @cond DO_NOT_INCLUDE_WITH_DOXYGEN

/***************************************************************************//**
 * \addtogroup sl_psa_drivers
 * \{
 ******************************************************************************/

/***************************************************************************//**
 * \addtogroup sl_psa_drivers_se
 * \{
 ******************************************************************************/

#include "sli_psa_driver_features.h"

#if defined(SLI_MBEDTLS_DEVICE_HSE) && defined(SLI_PSA_DRIVER_FEATURE_PAKE)

// Keep types free of psa/crypto.h and psa/crypto_extra.h: this header is pulled
// in via sli_se_transparent_types.h from early PSA context headers (e.g. sha1_alt.h).
#include "psa/crypto_driver_common.h"
#include "sl_se_manager_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Same layout size as MBEDTLS_PSA_JPAKE_BUFFER_SIZE: ECParameters (3) plus
// length-prefixed KEY_SHARE / ZK_PUBLIC / ZK_PROOF for two parties.
#define SLI_SE_PSA_JPAKE_BUFFER_SIZE  ((3 + 1 + 65 + 1 + 65 + 1 + 32) * 2)

typedef struct {
  psa_algorithm_t alg;
  sl_se_ecjpake_role_t role;
  sl_se_command_context_t cmd_ctx;
  sl_se_ecjpake_context_t ctx;
  uint8_t buffer[SLI_SE_PSA_JPAKE_BUFFER_SIZE];
  size_t buffer_length;
  size_t buffer_offset;
} sli_se_driver_pake_operation_t;

#ifdef __cplusplus
}
#endif

#endif // SLI_MBEDTLS_DEVICE_HSE && SLI_PSA_DRIVER_FEATURE_PAKE

/** \} (end addtogroup sl_psa_drivers_se) */
/** \} (end addtogroup sl_psa_drivers) */

/// @endcond

#endif // SLI_SE_DRIVER_PAKE_H

// Function prototypes need PAKE driver types from psa/crypto_extra.h. Keep them
// outside the types include-guard so a later re-include (after crypto_extra.h)
// still declares them when this header was first pulled in early via crypto.h.
#if defined(SLI_MBEDTLS_DEVICE_HSE) && defined(SLI_PSA_DRIVER_FEATURE_PAKE) \
  && defined(PSA_CRYPTO_EXTRA_H) && !defined(SLI_SE_DRIVER_PAKE_FUNCTIONS_H)
#define SLI_SE_DRIVER_PAKE_FUNCTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

psa_status_t sli_se_driver_pake_setup(
  sli_se_driver_pake_operation_t *operation,
  const psa_crypto_driver_pake_inputs_t *inputs);

psa_status_t sli_se_driver_pake_output(
  sli_se_driver_pake_operation_t *operation,
  psa_crypto_driver_pake_step_t step,
  uint8_t *output,
  size_t output_size,
  size_t *output_length);

psa_status_t sli_se_driver_pake_input(
  sli_se_driver_pake_operation_t *operation,
  psa_crypto_driver_pake_step_t step,
  const uint8_t *input,
  size_t input_length);

psa_status_t sli_se_driver_pake_get_implicit_key(
  sli_se_driver_pake_operation_t *operation,
  uint8_t *output,
  size_t output_size,
  size_t *output_length);

psa_status_t sli_se_driver_pake_abort(
  sli_se_driver_pake_operation_t *operation);

#ifdef __cplusplus
}
#endif

#endif // SLI_SE_DRIVER_PAKE_FUNCTIONS_H
