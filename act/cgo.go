//go:build act

package act

/*
#cgo LDFLAGS: -L${SRCDIR}/ffi/target/release -lcbp_act_ffi -lm -ldl -lpthread
#include "ffi/act.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// Available reports whether ACT crypto is linked into this binary.
func Available() bool { return true }

func code(rc C.int32_t) error {
	switch rc {
	case C.ACT_OK:
		return nil
	case C.ACT_ERR_INVALID_PROOF:
		return ErrInvalidProof
	case C.ACT_ERR_MALFORMED:
		return ErrMalformed
	case C.ACT_ERR_INVALID_AMOUNT:
		return ErrInvalidAmount
	default:
		return ErrInternal
	}
}

// in pins b for the duration of a C call and returns its pointer and length.
func in(p *runtime.Pinner, b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	p.Pin(&b[0])
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

func take(b C.ActBuf) []byte {
	defer C.act_buf_free(b)
	return C.GoBytes(unsafe.Pointer(b.ptr), C.int(b.len))
}

// GenerateKey creates a new issuer keypair (CBOR private key, CBOR public key).
func GenerateKey() (sk, pk []byte, err error) {
	var skb, pkb C.ActBuf
	if err := code(C.act_keygen(&skb, &pkb)); err != nil {
		return nil, nil, err
	}
	return take(skb), take(pkb), nil
}

// Context derives the context scalar bound into credentials issued with ctx.
func Context(ctx []byte) ([32]byte, error) {
	var p runtime.Pinner
	defer p.Unpin()
	var outb [32]byte
	cp, cl := in(&p, ctx)
	err := code(C.act_context(cp, cl, (*C.uint8_t)(unsafe.Pointer(&outb[0]))))
	return outb, err
}

// Issue signs a client issuance request for credits bound to ctx.
func Issue(params string, sk, req []byte, credits uint64, ctx []byte) ([]byte, error) {
	var p runtime.Pinner
	defer p.Unpin()
	pp, pl := in(&p, []byte(params))
	sp, sl := in(&p, sk)
	rp, rl := in(&p, req)
	cp, cl := in(&p, ctx)
	var resp C.ActBuf
	if err := code(C.act_issue(pp, pl, sp, sl, rp, rl, C.uint64_t(credits), cp, cl, &resp)); err != nil {
		return nil, err
	}
	return take(resp), nil
}

// VerifySpend checks a spend proof and reports its nullifier, context and charge.
// It does not record the nullifier; callers must do that atomically.
func VerifySpend(params string, sk, proof []byte) (SpendInfo, error) {
	var p runtime.Pinner
	defer p.Unpin()
	pp, pl := in(&p, []byte(params))
	sp, sl := in(&p, sk)
	fp, fl := in(&p, proof)
	var info SpendInfo
	var charge C.uint64_t
	err := code(C.act_verify_spend(pp, pl, sp, sl, fp, fl,
		(*C.uint8_t)(unsafe.Pointer(&info.Nullifier[0])),
		(*C.uint8_t)(unsafe.Pointer(&info.Context[0])),
		&charge))
	info.Charge = uint64(charge)
	return info, err
}

// Refund verifies a spend proof and issues a refund returning `returned`
// credits (0 <= returned <= charge) to the client.
func Refund(params string, sk, proof []byte, returned uint64) ([]byte, error) {
	var p runtime.Pinner
	defer p.Unpin()
	pp, pl := in(&p, []byte(params))
	sp, sl := in(&p, sk)
	fp, fl := in(&p, proof)
	var out C.ActBuf
	if err := code(C.act_refund(pp, pl, sp, sl, fp, fl, C.uint64_t(returned), &out)); err != nil {
		return nil, err
	}
	return take(out), nil
}

// ClientIssuanceRequest starts issuance. Keep pre secret; send req to the issuer.
func ClientIssuanceRequest(params string) (pre, req []byte, err error) {
	var p runtime.Pinner
	defer p.Unpin()
	pp, pl := in(&p, []byte(params))
	var preb, reqb C.ActBuf
	if err := code(C.act_client_issuance_request(pp, pl, &preb, &reqb)); err != nil {
		return nil, nil, err
	}
	return take(preb), take(reqb), nil
}

// ClientFinalizeIssuance verifies the issuer response and returns the credential.
func ClientFinalizeIssuance(params string, pk, pre, req, resp []byte) ([]byte, error) {
	var p runtime.Pinner
	defer p.Unpin()
	pp, pl := in(&p, []byte(params))
	kp, kl := in(&p, pk)
	ep, el := in(&p, pre)
	rp, rl := in(&p, req)
	sp, sl := in(&p, resp)
	var out C.ActBuf
	if err := code(C.act_client_finalize_issuance(pp, pl, kp, kl, ep, el, rp, rl, sp, sl, &out)); err != nil {
		return nil, err
	}
	return take(out), nil
}

// ClientProveSpend spends amount credits from token. The token must not be reused.
func ClientProveSpend(params string, token []byte, amount uint64) (proof, prerefund []byte, err error) {
	var p runtime.Pinner
	defer p.Unpin()
	pp, pl := in(&p, []byte(params))
	tp, tl := in(&p, token)
	var proofb, preb C.ActBuf
	if err := code(C.act_client_prove_spend(pp, pl, tp, tl, C.uint64_t(amount), &proofb, &preb)); err != nil {
		return nil, nil, err
	}
	return take(proofb), take(preb), nil
}

// ClientFinalizeRefund turns an issuer refund into the next credential.
func ClientFinalizeRefund(params string, pk, prerefund, proof, refund []byte) ([]byte, error) {
	var p runtime.Pinner
	defer p.Unpin()
	pp, pl := in(&p, []byte(params))
	kp, kl := in(&p, pk)
	ep, el := in(&p, prerefund)
	fp, fl := in(&p, proof)
	rp, rl := in(&p, refund)
	var out C.ActBuf
	if err := code(C.act_client_finalize_refund(pp, pl, kp, kl, ep, el, fp, fl, rp, rl, &out)); err != nil {
		return nil, err
	}
	return take(out), nil
}

// ClientBalance reads a credential's balance.
func ClientBalance(token []byte) (uint64, error) {
	var p runtime.Pinner
	defer p.Unpin()
	tp, tl := in(&p, token)
	var bal C.uint64_t
	err := code(C.act_client_balance(tp, tl, &bal))
	return uint64(bal), err
}
