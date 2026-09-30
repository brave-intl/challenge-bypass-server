/* C ABI for cbp-act-ffi. See src/lib.rs for semantics. */
#ifndef CBP_ACT_FFI_H
#define CBP_ACT_FFI_H

#include <stddef.h>
#include <stdint.h>

#define ACT_OK 0
#define ACT_ERR_INVALID_PROOF 1
#define ACT_ERR_MALFORMED 3
#define ACT_ERR_INVALID_AMOUNT 4
#define ACT_ERR_INTERNAL 5

typedef struct {
  uint8_t *ptr;
  size_t len;
} ActBuf;

void act_buf_free(ActBuf buf);

int32_t act_keygen(ActBuf *sk_out, ActBuf *pk_out);
int32_t act_context(const uint8_t *ctx, size_t ctx_len, uint8_t *ctx_out);
int32_t act_issue(const uint8_t *params, size_t params_len,
                  const uint8_t *sk, size_t sk_len,
                  const uint8_t *req, size_t req_len,
                  uint64_t amount,
                  const uint8_t *ctx, size_t ctx_len,
                  ActBuf *resp_out);
int32_t act_verify_spend(const uint8_t *params, size_t params_len,
                         const uint8_t *sk, size_t sk_len,
                         const uint8_t *proof, size_t proof_len,
                         uint8_t *nullifier_out, uint8_t *ctx_out,
                         uint64_t *charge_out);
int32_t act_refund(const uint8_t *params, size_t params_len,
                   const uint8_t *sk, size_t sk_len,
                   const uint8_t *proof, size_t proof_len,
                   uint64_t returned,
                   ActBuf *refund_out);

int32_t act_client_issuance_request(const uint8_t *params, size_t params_len,
                                    ActBuf *pre_out, ActBuf *req_out);
int32_t act_client_finalize_issuance(const uint8_t *params, size_t params_len,
                                     const uint8_t *pk, size_t pk_len,
                                     const uint8_t *pre, size_t pre_len,
                                     const uint8_t *req, size_t req_len,
                                     const uint8_t *resp, size_t resp_len,
                                     ActBuf *token_out);
int32_t act_client_prove_spend(const uint8_t *params, size_t params_len,
                               const uint8_t *token, size_t token_len,
                               uint64_t amount,
                               ActBuf *proof_out, ActBuf *prerefund_out);
int32_t act_client_finalize_refund(const uint8_t *params, size_t params_len,
                                   const uint8_t *pk, size_t pk_len,
                                   const uint8_t *prerefund, size_t prerefund_len,
                                   const uint8_t *proof, size_t proof_len,
                                   const uint8_t *refund, size_t refund_len,
                                   ActBuf *token_out);
int32_t act_client_balance(const uint8_t *token, size_t token_len,
                           uint64_t *balance_out);

#endif
