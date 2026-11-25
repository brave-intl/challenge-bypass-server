//! C ABI over `anonymous-credit-tokens` (ACT) for challenge-bypass-server.
//!
//! Values cross the boundary as bytes. Protocol messages use the crate's CBOR
//! encoding, credit amounts are u64, and scalars such as the nullifier and the
//! context are 32-byte little-endian encodings. Output buffers are allocated
//! here and must be released with `act_buf_free`.
//!
//! The server-side calls (`act_issue`, `act_verify_spend`, `act_refund`) are
//! what challenge-bypass-server uses. The `act_client_*` calls exist so the Go
//! side can exercise the full protocol in tests and as a reference for clients.

use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::sync::{Arc, OnceLock, RwLock};

use anonymous_credit_tokens::{
    CreditToken, ErrorCode, IssuanceRequest, IssuanceResponse, Params, PreIssuance, PreRefund,
    PrivateKey, PublicKey, Refund, Scalar, SpendProof, credit_to_scalar, scalar_to_credit,
};
use rand_core::OsRng;

// Re-exported so every challenge-bypass-ristretto-ffi C symbol is included in
// this staticlib. The Go ristretto bindings link this staticlib under the
// ristretto crate's library name.
pub use challenge_bypass_ristretto_ffi;

/// Bit length of credit amounts. Balances and charges must be < 2^L.
/// Spend proofs are 32 * (14 + 4L) bytes, so L = 32 gives ~4.5 KB proofs.
pub const L: usize = 32;

pub const ACT_OK: i32 = 0;
pub const ACT_ERR_INVALID_PROOF: i32 = 1;
pub const ACT_ERR_MALFORMED: i32 = 3;
pub const ACT_ERR_INVALID_AMOUNT: i32 = 4;
pub const ACT_ERR_INTERNAL: i32 = 5;

const CONTEXT_KDF: &str = "brave challenge-bypass-server ACT credential context v1";
const MAX_PARAMS_CACHE: usize = 256;

#[repr(C)]
pub struct ActBuf {
    pub ptr: *mut u8,
    pub len: usize,
}

impl ActBuf {
    fn from_vec(v: Vec<u8>) -> ActBuf {
        let boxed = v.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        ActBuf { ptr, len }
    }
}

/// Releases a buffer returned by any `act_*` function.
///
/// # Safety
/// `buf` must have been produced by this library and not freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_buf_free(buf: ActBuf) {
    if !buf.ptr.is_null() {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf.ptr, buf.len)) });
    }
}

type Res<T> = Result<T, i32>;

fn guard(f: impl FnOnce() -> Res<()>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => ACT_OK,
        Ok(Err(code)) => code,
        Err(_) => ACT_ERR_INTERNAL,
    }
}

unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

fn act_err(e: ErrorCode) -> i32 {
    match e {
        ErrorCode::InvalidProof | ErrorCode::NullifierReuse => ACT_ERR_INVALID_PROOF,
        ErrorCode::MalformedRequest => ACT_ERR_MALFORMED,
        ErrorCode::InvalidAmount => ACT_ERR_INVALID_AMOUNT,
    }
}

fn cbor_err<E>(_: E) -> i32 {
    ACT_ERR_MALFORMED
}

/// Parses "organization:service:deployment:version" into cached `Params`.
/// Building `Params` hashes four points and precomputes tables, so each
/// `Params` is cached behind an `RwLock` and built outside the lock.
fn params(ptr: *const u8, len: usize) -> Res<Arc<Params>> {
    static CACHE: OnceLock<RwLock<HashMap<String, Arc<Params>>>> = OnceLock::new();
    let s = std::str::from_utf8(unsafe { bytes(ptr, len) }).map_err(cbor_err)?;
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 4 || parts.iter().any(|p| p.is_empty()) {
        return Err(ACT_ERR_MALFORMED);
    }
    let lock = CACHE.get_or_init(Default::default);
    {
        let cache = lock.read().map_err(|_| ACT_ERR_INTERNAL)?;
        if let Some(p) = cache.get(s) {
            return Ok(p.clone());
        }
    }
    // Params::new uses about 300 KB of stack, more than musl's default 128 KB
    // thread stack. Build each new Params on a thread with a 1 MiB stack.
    let (p0, p1, p2, p3) = (
        parts[0].to_owned(),
        parts[1].to_owned(),
        parts[2].to_owned(),
        parts[3].to_owned(),
    );
    let built = std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(move || Arc::new(Params::new(&p0, &p1, &p2, &p3)))
        .map_err(|_| ACT_ERR_INTERNAL)?
        .join()
        .map_err(|_| ACT_ERR_INTERNAL)?;
    let mut cache = lock.write().map_err(|_| ACT_ERR_INTERNAL)?;
    if let Some(p) = cache.get(s) {
        return Ok(p.clone());
    }
    if cache.len() < MAX_PARAMS_CACHE {
        cache.insert(s.to_owned(), built.clone());
    }
    Ok(built)
}

fn context_scalar(ctx: &[u8]) -> Scalar {
    let mut wide = [0u8; 64];
    let mut h = blake3::Hasher::new_derive_key(CONTEXT_KDF);
    h.update(ctx);
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn credits(amount: u64) -> Res<Scalar> {
    credit_to_scalar::<L>(amount as u128).map_err(act_err)
}

fn private_key(ptr: *const u8, len: usize) -> Res<PrivateKey> {
    PrivateKey::from_cbor(unsafe { bytes(ptr, len) }).map_err(cbor_err)
}

fn public_key(ptr: *const u8, len: usize) -> Res<PublicKey> {
    PublicKey::from_cbor(unsafe { bytes(ptr, len) }).map_err(cbor_err)
}

fn spend_proof(ptr: *const u8, len: usize) -> Res<SpendProof<L>> {
    SpendProof::<L>::from_cbor(unsafe { bytes(ptr, len) }).map_err(cbor_err)
}

fn out(dst: *mut ActBuf, v: Vec<u8>) -> Res<()> {
    if dst.is_null() {
        return Err(ACT_ERR_INTERNAL);
    }
    unsafe { *dst = ActBuf::from_vec(v) };
    Ok(())
}

/// Writes two output buffers. Both pointers are checked before either buffer
/// is handed across the C ABI, so a null pointer never leaks the other buffer.
fn out2(dst1: *mut ActBuf, v1: Vec<u8>, dst2: *mut ActBuf, v2: Vec<u8>) -> Res<()> {
    if dst1.is_null() || dst2.is_null() {
        return Err(ACT_ERR_INTERNAL);
    }
    unsafe {
        *dst1 = ActBuf::from_vec(v1);
        *dst2 = ActBuf::from_vec(v2);
    }
    Ok(())
}

fn write_bytes32(dst: *mut u8, src: &[u8; 32]) -> Res<()> {
    if dst.is_null() {
        return Err(ACT_ERR_INTERNAL);
    }
    unsafe { slice::from_raw_parts_mut(dst, 32) }.copy_from_slice(src);
    Ok(())
}

// ---------------------------------------------------------------------------
// Issuer (server) operations
// ---------------------------------------------------------------------------

/// Generates a new issuer keypair (CBOR-encoded private and public keys).
///
/// # Safety
/// Output pointers must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_keygen(sk_out: *mut ActBuf, pk_out: *mut ActBuf) -> i32 {
    guard(|| {
        let sk = PrivateKey::random(OsRng);
        let pk_bytes = sk.public().to_cbor().map_err(cbor_err)?;
        let sk_bytes = sk.to_cbor().map_err(cbor_err)?;
        out2(sk_out, sk_bytes, pk_out, pk_bytes)
    })
}

/// Derives the 32-byte context scalar the issuer binds into credentials.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. `ctx_out` must be valid
/// for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_context(ctx: *const u8, ctx_len: usize, ctx_out: *mut u8) -> i32 {
    guard(|| {
        let s = context_scalar(unsafe { bytes(ctx, ctx_len) });
        write_bytes32(ctx_out, s.as_bytes())
    })
}

/// Signs a client issuance request for `amount` credits bound to `ctx`.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. `resp_out` must be valid
/// for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_issue(
    params_ptr: *const u8,
    params_len: usize,
    sk: *const u8,
    sk_len: usize,
    req: *const u8,
    req_len: usize,
    amount: u64,
    ctx: *const u8,
    ctx_len: usize,
    resp_out: *mut ActBuf,
) -> i32 {
    guard(|| {
        let params = params(params_ptr, params_len)?;
        let sk = private_key(sk, sk_len)?;
        let req = IssuanceRequest::from_cbor(unsafe { bytes(req, req_len) }).map_err(cbor_err)?;
        let ctx = context_scalar(unsafe { bytes(ctx, ctx_len) });
        let resp = sk
            .issue::<L>(&params, &req, credits(amount)?, ctx, OsRng)
            .map_err(act_err)?;
        out(resp_out, resp.to_cbor().map_err(cbor_err)?)
    })
}

/// Verifies a spend proof without releasing anything to the client.
///
/// The crate only verifies inside `refund`, so `act_verify_spend` computes a
/// zero refund and discards it. On success it writes the nullifier and the
/// context, 32 bytes each, and the charged amount.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. Output pointers must be
/// valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_verify_spend(
    params_ptr: *const u8,
    params_len: usize,
    sk: *const u8,
    sk_len: usize,
    proof: *const u8,
    proof_len: usize,
    nullifier_out: *mut u8,
    ctx_out: *mut u8,
    charge_out: *mut u64,
) -> i32 {
    guard(|| {
        if nullifier_out.is_null() || ctx_out.is_null() || charge_out.is_null() {
            return Err(ACT_ERR_INTERNAL);
        }
        let params = params(params_ptr, params_len)?;
        let sk = private_key(sk, sk_len)?;
        let proof = spend_proof(proof, proof_len)?;
        sk.refund::<L>(&params, &proof, Scalar::ZERO, OsRng)
            .map_err(act_err)?;
        let charge = scalar_to_credit::<L>(&proof.charge()).map_err(act_err)?;
        write_bytes32(nullifier_out, proof.nullifier().as_bytes())?;
        write_bytes32(ctx_out, proof.context().as_bytes())?;
        unsafe { *charge_out = charge as u64 };
        Ok(())
    })
}

/// Verifies a spend proof and issues a refund returning `returned` credits
/// (0 <= returned <= charge) to the client's next credential.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. `refund_out` must be valid
/// for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_refund(
    params_ptr: *const u8,
    params_len: usize,
    sk: *const u8,
    sk_len: usize,
    proof: *const u8,
    proof_len: usize,
    returned: u64,
    refund_out: *mut ActBuf,
) -> i32 {
    guard(|| {
        let params = params(params_ptr, params_len)?;
        let sk = private_key(sk, sk_len)?;
        let proof = spend_proof(proof, proof_len)?;
        let refund = sk
            .refund::<L>(&params, &proof, credits(returned)?, OsRng)
            .map_err(act_err)?;
        out(refund_out, refund.to_cbor().map_err(cbor_err)?)
    })
}

// ---------------------------------------------------------------------------
// Client operations (tests and reference only)
// ---------------------------------------------------------------------------

/// Starts issuance. Returns the client's secret state and the request to send.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. Output pointers must be
/// valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_client_issuance_request(
    params_ptr: *const u8,
    params_len: usize,
    pre_out: *mut ActBuf,
    req_out: *mut ActBuf,
) -> i32 {
    guard(|| {
        let params = params(params_ptr, params_len)?;
        let pre = PreIssuance::random(OsRng);
        let req = pre.request(&params, OsRng);
        let req_bytes = req.to_cbor().map_err(cbor_err)?;
        let pre_bytes = pre.to_cbor().map_err(cbor_err)?;
        out2(pre_out, pre_bytes, req_out, req_bytes)
    })
}

/// Finishes issuance. Verifies the issuer response and returns the credential.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. `token_out` must be valid
/// for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_client_finalize_issuance(
    params_ptr: *const u8,
    params_len: usize,
    pk: *const u8,
    pk_len: usize,
    pre: *const u8,
    pre_len: usize,
    req: *const u8,
    req_len: usize,
    resp: *const u8,
    resp_len: usize,
    token_out: *mut ActBuf,
) -> i32 {
    guard(|| {
        let params = params(params_ptr, params_len)?;
        let pk = public_key(pk, pk_len)?;
        let pre = PreIssuance::from_cbor(unsafe { bytes(pre, pre_len) }).map_err(cbor_err)?;
        let req = IssuanceRequest::from_cbor(unsafe { bytes(req, req_len) }).map_err(cbor_err)?;
        let resp =
            IssuanceResponse::from_cbor(unsafe { bytes(resp, resp_len) }).map_err(cbor_err)?;
        let token = pre
            .to_credit_token::<L>(&params, &pk, &req, &resp)
            .map_err(act_err)?;
        out(token_out, token.to_cbor().map_err(cbor_err)?)
    })
}

/// Spends `amount` credits from a credential. Returns the proof to send and the
/// client's secret refund state. The input credential must not be reused.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. Output pointers must be
/// valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_client_prove_spend(
    params_ptr: *const u8,
    params_len: usize,
    token: *const u8,
    token_len: usize,
    amount: u64,
    proof_out: *mut ActBuf,
    prerefund_out: *mut ActBuf,
) -> i32 {
    guard(|| {
        let params = params(params_ptr, params_len)?;
        let token = CreditToken::from_cbor(unsafe { bytes(token, token_len) }).map_err(cbor_err)?;
        let (proof, pre) = token
            .prove_spend::<L>(&params, credits(amount)?, OsRng)
            .map_err(act_err)?;
        let proof_bytes = proof.to_cbor().map_err(cbor_err)?;
        let pre_bytes = pre.to_cbor().map_err(cbor_err)?;
        out2(proof_out, proof_bytes, prerefund_out, pre_bytes)
    })
}

/// Turns an issuer refund into the client's next credential.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. `token_out` must be valid
/// for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_client_finalize_refund(
    params_ptr: *const u8,
    params_len: usize,
    pk: *const u8,
    pk_len: usize,
    prerefund: *const u8,
    prerefund_len: usize,
    proof: *const u8,
    proof_len: usize,
    refund: *const u8,
    refund_len: usize,
    token_out: *mut ActBuf,
) -> i32 {
    guard(|| {
        let params = params(params_ptr, params_len)?;
        let pk = public_key(pk, pk_len)?;
        let pre =
            PreRefund::from_cbor(unsafe { bytes(prerefund, prerefund_len) }).map_err(cbor_err)?;
        let proof = spend_proof(proof, proof_len)?;
        let refund = Refund::from_cbor(unsafe { bytes(refund, refund_len) }).map_err(cbor_err)?;
        let token = pre
            .to_credit_token::<L>(&params, &proof, &refund, &pk)
            .map_err(act_err)?;
        out(token_out, token.to_cbor().map_err(cbor_err)?)
    })
}

/// Reads the balance of a credential.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. `balance_out` must be valid
/// for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_client_balance(
    token: *const u8,
    token_len: usize,
    balance_out: *mut u64,
) -> i32 {
    guard(|| {
        if balance_out.is_null() {
            return Err(ACT_ERR_INTERNAL);
        }
        let token = CreditToken::from_cbor(unsafe { bytes(token, token_len) }).map_err(cbor_err)?;
        let c = scalar_to_credit::<L>(&token.credits()).map_err(act_err)?;
        unsafe { *balance_out = c as u64 };
        Ok(())
    })
}

/// Reads the 32-byte nullifier from a spend proof without verifying it.
/// Clients can use this to recover a refund by nullifier if the spend response was lost.
///
/// # Safety
/// Input pointers must be valid for `*_len` bytes. `nullifier_out` must be
/// valid for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn act_client_spend_nullifier(
    proof: *const u8,
    proof_len: usize,
    nullifier_out: *mut u8,
) -> i32 {
    guard(|| {
        let proof = spend_proof(proof, proof_len)?;
        write_bytes32(nullifier_out, proof.nullifier().as_bytes())
    })
}
