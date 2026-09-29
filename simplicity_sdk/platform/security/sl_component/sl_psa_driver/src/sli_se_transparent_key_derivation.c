/***************************************************************************//**
 * @file
 * @brief Silicon Labs PSA Crypto Transparent Driver Key derivation functions.
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
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

#include "sli_psa_driver_features.h"

#if defined(SLI_MBEDTLS_DEVICE_HSE)

#include "psa/crypto.h"

#include "sli_se_driver_key_derivation.h"
#include "sli_se_transparent_functions.h"

#include <string.h>

//------------------------------------------------------------------------------
// Driver entry points

psa_status_t sli_se_transparent_key_agreement(
  psa_algorithm_t alg,
  const psa_key_attributes_t *attributes,
  const uint8_t *key_buffer,
  size_t key_buffer_size,
  const uint8_t *peer_key,
  size_t peer_key_length,
  uint8_t *output,
  size_t output_size,
  size_t *output_length)
{
  return sli_se_driver_key_agreement(alg,
                                     attributes,
                                     key_buffer,
                                     key_buffer_size,
                                     peer_key,
                                     peer_key_length,
                                     output,
                                     output_size,
                                     output_length);
}

#if defined(SLI_PSA_DRIVER_FEATURE_PAKE)

psa_status_t sli_se_transparent_key_derivation_input_bytes(
  sli_se_transparent_key_derivation_operation_t *operation,
  psa_algorithm_t alg,
  psa_key_derivation_step_t step,
  const uint8_t *data,
  size_t data_length)
{
  if (operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  /* Only accelerate the SE-specific case: SECRET is already the 32-byte TLS PMS
   * from GEN_SESSIONKEY. The standard 65-byte EC-point path stays builtin. */
  if (alg != PSA_ALG_TLS12_ECJPAKE_TO_PMS) {
    return PSA_ERROR_NOT_SUPPORTED;
  }
  if (step != PSA_KEY_DERIVATION_INPUT_SECRET) {
    return PSA_ERROR_NOT_SUPPORTED;
  }
  if ((data == NULL) || (data_length != PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE)) {
    return PSA_ERROR_NOT_SUPPORTED;
  }
  if (operation->pms_set != 0) {
    return PSA_ERROR_BAD_STATE;
  }

  memcpy(operation->pms, data, PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE);
  operation->pms_set = 1;
  return PSA_SUCCESS;
}

psa_status_t sli_se_transparent_key_derivation_output_bytes(
  sli_se_transparent_key_derivation_operation_t *operation,
  uint8_t *output,
  size_t output_length)
{
  if ((operation == NULL) || (output == NULL)) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  if (operation->pms_set == 0) {
    return PSA_ERROR_BAD_STATE;
  }
  if (output_length != PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  memcpy(output, operation->pms, PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE);
  return PSA_SUCCESS;
}

psa_status_t sli_se_transparent_key_derivation_abort(
  sli_se_transparent_key_derivation_operation_t *operation)
{
  if (operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }
  memset(operation, 0, sizeof(*operation));
  return PSA_SUCCESS;
}

#endif /* SLI_PSA_DRIVER_FEATURE_PAKE */

#endif // SLI_MBEDTLS_DEVICE_HSE
