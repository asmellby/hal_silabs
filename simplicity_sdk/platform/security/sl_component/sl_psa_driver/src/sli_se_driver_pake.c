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

#include "sli_psa_driver_features.h"

#if defined(SLI_MBEDTLS_DEVICE_HSE) && defined(SLI_PSA_DRIVER_FEATURE_PAKE)

#include "psa/crypto.h"
#include "psa/crypto_extra.h"

#include "sli_se_driver_pake.h"
#include "sli_psa_driver_common.h"

#include "sl_se_manager.h"
#include "sl_se_manager_key_derivation.h"

#include <string.h>

// -----------------------------------------------------------------------------
// Macros and constants

// Length-prefixed round records use a single byte for the step payload size.
#define SLI_SE_PAKE_MAX_STEP_LENGTH  (255)

// Only client/server identity strings are supported (same as builtin PAKE).
static const uint8_t jpake_server_id[] = { 's', 'e', 'r', 'v', 'e', 'r' };
static const uint8_t jpake_client_id[] = { 'c', 'l', 'i', 'e', 'n', 't' };

// -----------------------------------------------------------------------------
// Static helpers

static psa_status_t sli_se_pake_validate_step(psa_crypto_driver_pake_step_t step)
{
  if ((step < PSA_JPAKE_X1_STEP_KEY_SHARE)
      || (step > PSA_JPAKE_X4S_STEP_ZK_PROOF)) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  return PSA_SUCCESS;
}

static psa_status_t sli_se_ecjpake_to_psa_status(sl_status_t status)
{
  switch (status) {
    case SL_STATUS_OK:
      return PSA_SUCCESS;
    case SL_STATUS_INVALID_PARAMETER:
      return PSA_ERROR_INVALID_ARGUMENT;
    case SL_STATUS_NOT_SUPPORTED:
      return PSA_ERROR_NOT_SUPPORTED;
    case SL_STATUS_WOULD_OVERFLOW:
      return PSA_ERROR_BUFFER_TOO_SMALL;
    // Match mbedtls_ecjpake_to_psa_error: a failed Schnorr proof check is an
    // invalid signature, while malformed key shares are invalid data.
    case SL_STATUS_INVALID_SIGNATURE:
      return PSA_ERROR_INVALID_SIGNATURE;
    case SL_STATUS_FAIL:
    case SL_STATUS_INVALID_KEY:
      return PSA_ERROR_DATA_INVALID;
    default:
      return PSA_ERROR_HARDWARE_FAILURE;
  }
}

static psa_status_t sli_se_pake_clear_buffer(sli_se_driver_pake_operation_t *operation)
{
  sli_psa_zeroize(operation->buffer, sizeof(operation->buffer));
  operation->buffer_length = 0;
  operation->buffer_offset = 0;
  return PSA_SUCCESS;
}

// -----------------------------------------------------------------------------
// Driver entry points

psa_status_t sli_se_driver_pake_setup(
  sli_se_driver_pake_operation_t *operation,
  const psa_crypto_driver_pake_inputs_t *inputs)
{
  psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
  sl_status_t sl_status;
  size_t password_len = 0;
  size_t user_len = 0;
  size_t peer_len = 0;
  size_t actual_password_len = 0;
  size_t actual_user_len = 0;
  size_t actual_peer_len = 0;
  uint8_t password[32] = { 0 };
  uint8_t user[32] = { 0 };
  uint8_t peer[32] = { 0 };
  psa_pake_cipher_suite_t cipher_suite = psa_pake_cipher_suite_init();
  sl_se_ecjpake_role_t role;

  if (operation == NULL || inputs == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  memset(operation, 0, sizeof(*operation));

  status = psa_crypto_driver_pake_get_password_len(inputs, &password_len);
  if (status != PSA_SUCCESS) {
    return status;
  }

  // SE Manager copies at most 32 bytes into the EC-JPAKE context.
  if (password_len == 0 || password_len > sizeof(password)) {
    return PSA_ERROR_NOT_SUPPORTED;
  }

  status = psa_crypto_driver_pake_get_user_len(inputs, &user_len);
  if (status != PSA_SUCCESS) {
    return status;
  }

  status = psa_crypto_driver_pake_get_peer_len(inputs, &peer_len);
  if (status != PSA_SUCCESS) {
    return status;
  }

  if (user_len > sizeof(user) || peer_len > sizeof(peer)) {
    return PSA_ERROR_NOT_SUPPORTED;
  }

  status = psa_crypto_driver_pake_get_cipher_suite(inputs, &cipher_suite);
  if (status != PSA_SUCCESS) {
    return status;
  }

  status = psa_crypto_driver_pake_get_password(inputs,
                                              password,
                                              sizeof(password),
                                              &actual_password_len);
  if (status != PSA_SUCCESS) {
    goto cleanup;
  }

  status = psa_crypto_driver_pake_get_user(inputs,
                                           user,
                                           sizeof(user),
                                           &actual_user_len);
  if (status != PSA_SUCCESS) {
    goto cleanup;
  }

  status = psa_crypto_driver_pake_get_peer(inputs,
                                           peer,
                                           sizeof(peer),
                                           &actual_peer_len);
  if (status != PSA_SUCCESS) {
    goto cleanup;
  }

  psa_algorithm_t cs_alg = psa_pake_cs_get_algorithm(&cipher_suite);
  psa_pake_primitive_t primitive = psa_pake_cs_get_primitive(&cipher_suite);

  // Unspecified primitive is invalid; non-secp256r1 J-PAKE is unsupported.
  if (primitive == 0) {
    status = PSA_ERROR_INVALID_ARGUMENT;
    goto cleanup;
  }

  if (!PSA_ALG_IS_JPAKE(cs_alg)
      || PSA_ALG_GET_HASH(cs_alg) != PSA_ALG_SHA_256
      || psa_pake_cs_get_family(&cipher_suite) != PSA_ECC_FAMILY_SECP_R1
      || psa_pake_cs_get_bits(&cipher_suite) != 256) {
    status = PSA_ERROR_NOT_SUPPORTED;
    goto cleanup;
  }

  {
    psa_pake_primitive_type_t type =
      (psa_pake_primitive_type_t)((primitive >> 24) & 0xffU);
    if (type != PSA_PAKE_PRIMITIVE_TYPE_ECC) {
      status = PSA_ERROR_NOT_SUPPORTED;
      goto cleanup;
    }
  }

  if (actual_user_len != sizeof(jpake_client_id)
      || actual_peer_len != sizeof(jpake_client_id)) {
    status = PSA_ERROR_NOT_SUPPORTED;
    goto cleanup;
  }

  if (memcmp(user, jpake_client_id, actual_user_len) == 0
      && memcmp(peer, jpake_server_id, actual_peer_len) == 0) {
    role = SL_SE_ECJPAKE_CLIENT;
  } else if (memcmp(user, jpake_server_id, actual_user_len) == 0
             && memcmp(peer, jpake_client_id, actual_peer_len) == 0) {
    role = SL_SE_ECJPAKE_SERVER;
  } else {
    status = PSA_ERROR_NOT_SUPPORTED;
    goto cleanup;
  }

  sl_status = sl_se_init_command_context(&operation->cmd_ctx);
  if (sl_status != SL_STATUS_OK) {
    status = PSA_ERROR_HARDWARE_FAILURE;
    goto cleanup;
  }

  sl_status = sl_se_ecjpake_init(&operation->ctx, &operation->cmd_ctx);
  if (sl_status != SL_STATUS_OK) {
    (void)sl_se_deinit_command_context(&operation->cmd_ctx);
    status = sli_se_ecjpake_to_psa_status(sl_status);
    goto cleanup;
  }

  sl_status = sl_se_ecjpake_setup(&operation->ctx,
                                  role,
                                  SL_SE_HASH_SHA256,
                                  SL_SE_KEY_TYPE_ECC_P256,
                                  password,
                                  actual_password_len);
  if (sl_status != SL_STATUS_OK) {
    (void)sl_se_ecjpake_free(&operation->ctx);
    (void)sl_se_deinit_command_context(&operation->cmd_ctx);
    status = sli_se_ecjpake_to_psa_status(sl_status);
    goto cleanup;
  }

  operation->alg = cs_alg;
  operation->role = role;
  operation->buffer_length = 0;
  operation->buffer_offset = 0;

  status = PSA_SUCCESS;

  cleanup:
  sli_psa_zeroize(password, sizeof(password));
  sli_psa_zeroize(user, sizeof(user));
  sli_psa_zeroize(peer, sizeof(peer));
  return status;
}

psa_status_t sli_se_driver_pake_output(
  sli_se_driver_pake_operation_t *operation,
  psa_crypto_driver_pake_step_t step,
  uint8_t *output,
  size_t output_size,
  size_t *output_length)
{
  psa_status_t status;
  sl_status_t sl_status;
  size_t length;
  size_t offset;

  if (operation == NULL || output == NULL || output_length == NULL
      || output_size == 0) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  status = sli_se_pake_validate_step(step);
  if (status != PSA_SUCCESS) {
    return status;
  }

  if (!PSA_ALG_IS_JPAKE(operation->alg)) {
    return PSA_ERROR_BAD_STATE;
  }

  /*
   * PSA PAKE exposes KEY_SHARE / ZK_PUBLIC / ZK_PROOF steps. SE Manager
   * produces a whole round buffer. Generate the round on the first KEY_SHARE
   * of that round, then slice length-prefixed records out of the buffer.
   */
  if (step == PSA_JPAKE_X1_STEP_KEY_SHARE) {
    sl_status = sl_se_ecjpake_write_round_one(&operation->ctx,
                                              operation->buffer,
                                              sizeof(operation->buffer),
                                              &operation->buffer_length);
    if (sl_status != SL_STATUS_OK) {
      return sli_se_ecjpake_to_psa_status(sl_status);
    }
    operation->buffer_offset = 0;
  } else if (step == PSA_JPAKE_X2S_STEP_KEY_SHARE) {
    sl_status = sl_se_ecjpake_write_round_two(&operation->ctx,
                                              operation->buffer,
                                              sizeof(operation->buffer),
                                              &operation->buffer_length);
    if (sl_status != SL_STATUS_OK) {
      return sli_se_ecjpake_to_psa_status(sl_status);
    }
    operation->buffer_offset = 0;
  }

  // Peek only; commit buffer_offset after the copy succeeds so a
  // BUFFER_TOO_SMALL retry does not skip the length byte.
  offset = operation->buffer_offset;

  if (step == PSA_JPAKE_X2S_STEP_KEY_SHARE
      && operation->role == SL_SE_ECJPAKE_SERVER) {
    // Skip ECParameters (3 bytes, RFC 8422 named_curve secp256r1).
    if (offset + 3 > operation->buffer_length) {
      return PSA_ERROR_DATA_CORRUPT;
    }
    offset += 3;
  }

  if (offset >= operation->buffer_length) {
    return PSA_ERROR_DATA_CORRUPT;
  }

  length = operation->buffer[offset];

  if (offset + 1 + length > operation->buffer_length) {
    return PSA_ERROR_DATA_CORRUPT;
  }

  if (output_size < length) {
    return PSA_ERROR_BUFFER_TOO_SMALL;
  }

  offset += 1;
  memcpy(output, operation->buffer + offset, length);
  *output_length = length;
  operation->buffer_offset = offset + length;

  if ((step == PSA_JPAKE_X2_STEP_ZK_PROOF)
      || (step == PSA_JPAKE_X2S_STEP_ZK_PROOF)) {
    (void)sli_se_pake_clear_buffer(operation);
  }

  return PSA_SUCCESS;
}

psa_status_t sli_se_driver_pake_input(
  sli_se_driver_pake_operation_t *operation,
  psa_crypto_driver_pake_step_t step,
  const uint8_t *input,
  size_t input_length)
{
  psa_status_t status;
  sl_status_t sl_status;

  if (operation == NULL || input == NULL || input_length == 0
      || input_length > SLI_SE_PAKE_MAX_STEP_LENGTH) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  status = sli_se_pake_validate_step(step);
  if (status != PSA_SUCCESS) {
    return status;
  }

  if (!PSA_ALG_IS_JPAKE(operation->alg)) {
    return PSA_ERROR_BAD_STATE;
  }

  /*
   * Buffer PSA step inputs into TLS EC-JPAKE round format, then call SE
   * Manager read_round_* on the last ZK_PROOF of each round.
   */
  if (step == PSA_JPAKE_X4S_STEP_KEY_SHARE
      && operation->role == SL_SE_ECJPAKE_CLIENT) {
    // Prepend ECParameters for client round-two input (secp256r1).
    const unsigned char ecparameters[3] = {
      3, /* named_curve */
      0, 23 /* secp256r1 */
    };

    if (operation->buffer_length + sizeof(ecparameters) > sizeof(operation->buffer)) {
      return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(operation->buffer + operation->buffer_length,
           ecparameters,
           sizeof(ecparameters));
    operation->buffer_length += sizeof(ecparameters);
  }

  if (operation->buffer_length + input_length + 1 > sizeof(operation->buffer)) {
    return PSA_ERROR_BUFFER_TOO_SMALL;
  }

  operation->buffer[operation->buffer_length] = (uint8_t)input_length;
  operation->buffer_length += 1;

  if (input_length > 0) {
    memcpy(operation->buffer + operation->buffer_length, input, input_length);
    operation->buffer_length += input_length;
  }

  if (step == PSA_JPAKE_X2_STEP_ZK_PROOF) {
    sl_status = sl_se_ecjpake_read_round_one(&operation->ctx,
                                             operation->buffer,
                                             operation->buffer_length);
    (void)sli_se_pake_clear_buffer(operation);
    if (sl_status != SL_STATUS_OK) {
      return sli_se_ecjpake_to_psa_status(sl_status);
    }
  } else if (step == PSA_JPAKE_X4S_STEP_ZK_PROOF) {
    sl_status = sl_se_ecjpake_read_round_two(&operation->ctx,
                                             operation->buffer,
                                             operation->buffer_length);
    (void)sli_se_pake_clear_buffer(operation);
    if (sl_status != SL_STATUS_OK) {
      return sli_se_ecjpake_to_psa_status(sl_status);
    }
  }

  return PSA_SUCCESS;
}

psa_status_t sli_se_driver_pake_get_implicit_key(
  sli_se_driver_pake_operation_t *operation,
  uint8_t *output,
  size_t output_size,
  size_t *output_length)
{
  sl_status_t sl_status;

  if (operation == NULL || output == NULL || output_length == NULL
      || output_size == 0) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  if (!PSA_ALG_IS_JPAKE(operation->alg)) {
    return PSA_ERROR_BAD_STATE;
  }

  // SE GEN_SESSIONKEY produces the TLS Premaster Secret (32 bytes).
  sl_status = sl_se_ecjpake_derive_secret(&operation->ctx,
                                          output,
                                          output_size,
                                          output_length);
  return sli_se_ecjpake_to_psa_status(sl_status);
}

psa_status_t sli_se_driver_pake_abort(
  sli_se_driver_pake_operation_t *operation)
{
  if (operation == NULL) {
    return PSA_ERROR_INVALID_ARGUMENT;
  }

  if (PSA_ALG_IS_JPAKE(operation->alg)) {
    (void)sl_se_ecjpake_free(&operation->ctx);
    (void)sl_se_deinit_command_context(&operation->cmd_ctx);
  }

  sli_psa_zeroize(operation, sizeof(*operation));
  return PSA_SUCCESS;
}

#endif // SLI_MBEDTLS_DEVICE_HSE && SLI_PSA_DRIVER_FEATURE_PAKE
