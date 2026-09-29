/***************************************************************************//**
 * @file
 * @brief Silicon Labs PSA Crypto Transparent Driver PAKE functions.
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

#include "sli_psa_driver_features.h"

#if defined(SLI_MBEDTLS_DEVICE_HSE) && defined(SLI_PSA_DRIVER_FEATURE_PAKE)

#include "psa/crypto.h"
#include "psa/crypto_extra.h"

#include "sli_se_transparent_types.h"
#include "sli_se_transparent_functions.h"
#include "sli_se_driver_pake.h"

psa_status_t sli_se_transparent_pake_setup(
  sli_se_transparent_pake_operation_t *operation,
  const psa_crypto_driver_pake_inputs_t *inputs)
{
  return sli_se_driver_pake_setup(operation, inputs);
}

psa_status_t sli_se_transparent_pake_output(
  sli_se_transparent_pake_operation_t *operation,
  psa_crypto_driver_pake_step_t step,
  uint8_t *output,
  size_t output_size,
  size_t *output_length)
{
  return sli_se_driver_pake_output(operation,
                                   step,
                                   output,
                                   output_size,
                                   output_length);
}

psa_status_t sli_se_transparent_pake_input(
  sli_se_transparent_pake_operation_t *operation,
  psa_crypto_driver_pake_step_t step,
  const uint8_t *input,
  size_t input_length)
{
  return sli_se_driver_pake_input(operation, step, input, input_length);
}

psa_status_t sli_se_transparent_pake_get_implicit_key(
  sli_se_transparent_pake_operation_t *operation,
  uint8_t *output,
  size_t output_size,
  size_t *output_length)
{
  return sli_se_driver_pake_get_implicit_key(operation,
                                             output,
                                             output_size,
                                             output_length);
}

psa_status_t sli_se_transparent_pake_abort(
  sli_se_transparent_pake_operation_t *operation)
{
  return sli_se_driver_pake_abort(operation);
}

#endif // SLI_MBEDTLS_DEVICE_HSE && SLI_PSA_DRIVER_FEATURE_PAKE
