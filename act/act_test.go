//go:build act

package act

import (
	"errors"
	"testing"
)

const testParams = "brave:cbp-act-test:test:2026-09-30"

// Full issue -> spend(hold) -> refund(unused) -> spend again cycle.
func TestCreditLifecycle(t *testing.T) {
	sk, pk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx := []byte("leo-premium-2026-10")

	pre, req, err := ClientIssuanceRequest(testParams)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Issue(testParams, sk, req, 1000, ctx)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ClientFinalizeIssuance(testParams, pk, pre, req, resp)
	if err != nil {
		t.Fatal(err)
	}
	if bal, _ := ClientBalance(token); bal != 1000 {
		t.Fatalf("balance = %d, want 1000", bal)
	}

	// Hold 300, actual cost 120 -> return 180.
	proof, prerefund, err := ClientProveSpend(testParams, token, 300)
	if err != nil {
		t.Fatal(err)
	}
	info, err := VerifySpend(testParams, sk, proof)
	if err != nil {
		t.Fatal(err)
	}
	wantCtx, _ := Context(ctx)
	if info.Charge != 300 || info.Context != wantCtx || info.Nullifier == [32]byte{} {
		t.Fatalf("unexpected spend info %+v", info)
	}

	if _, err := Refund(testParams, sk, proof, 301); !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("refund above charge: err = %v, want ErrInvalidAmount", err)
	}
	refund, err := Refund(testParams, sk, proof, 180)
	if err != nil {
		t.Fatal(err)
	}
	next, err := ClientFinalizeRefund(testParams, pk, prerefund, proof, refund)
	if err != nil {
		t.Fatal(err)
	}
	if bal, _ := ClientBalance(next); bal != 880 {
		t.Fatalf("balance after refund = %d, want 880", bal)
	}

	// Next spend has a fresh nullifier.
	proof2, _, err := ClientProveSpend(testParams, next, 880)
	if err != nil {
		t.Fatal(err)
	}
	info2, err := VerifySpend(testParams, sk, proof2)
	if err != nil {
		t.Fatal(err)
	}
	if info2.Nullifier == info.Nullifier {
		t.Fatal("nullifier reused across refund chain")
	}

	// Overspend is impossible to prove.
	if _, _, err := ClientProveSpend(testParams, next, 881); err == nil {
		t.Fatal("proved a spend larger than the balance")
	}
}

func TestVerifyRejects(t *testing.T) {
	sk, pk, _ := GenerateKey()
	otherSK, _, _ := GenerateKey()

	pre, req, _ := ClientIssuanceRequest(testParams)
	resp, _ := Issue(testParams, sk, req, 10, nil)
	token, err := ClientFinalizeIssuance(testParams, pk, pre, req, resp)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, _ := ClientProveSpend(testParams, token, 5)

	if _, err := VerifySpend(testParams, otherSK, proof); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("wrong key: err = %v, want ErrInvalidProof", err)
	}
	if _, err := VerifySpend("brave:other:test:2026-09-30", sk, proof); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("wrong params: err = %v, want ErrInvalidProof", err)
	}
	if _, err := VerifySpend(testParams, sk, proof[:len(proof)-1]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated proof: err = %v, want ErrMalformed", err)
	}
	if _, err := VerifySpend("no-colons", sk, proof); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad params: err = %v, want ErrMalformed", err)
	}
	if _, err := Issue(testParams, sk, req, 0, nil); !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("zero issuance: err = %v, want ErrInvalidAmount", err)
	}
	if _, err := Issue(testParams, sk, req, MaxCredits+1, nil); !errors.Is(err, ErrInvalidAmount) {
		t.Fatalf("oversized issuance: err = %v, want ErrInvalidAmount", err)
	}
}

// BenchmarkVerifySpend measures the server's per-spend verification cost.
func BenchmarkVerifySpend(b *testing.B) {
	sk, pk, _ := GenerateKey()
	pre, req, _ := ClientIssuanceRequest(testParams)
	resp, _ := Issue(testParams, sk, req, MaxCredits, nil)
	token, _ := ClientFinalizeIssuance(testParams, pk, pre, req, resp)
	proof, _, _ := ClientProveSpend(testParams, token, 1000)
	for b.Loop() {
		if _, err := VerifySpend(testParams, sk, proof); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(proof)), "proof-bytes")
}

// BenchmarkProveSpend measures the client's per-spend proving cost.
func BenchmarkProveSpend(b *testing.B) {
	sk, pk, _ := GenerateKey()
	pre, req, _ := ClientIssuanceRequest(testParams)
	resp, _ := Issue(testParams, sk, req, MaxCredits, nil)
	token, _ := ClientFinalizeIssuance(testParams, pk, pre, req, resp)
	for b.Loop() {
		if _, _, err := ClientProveSpend(testParams, token, 1000); err != nil {
			b.Fatal(err)
		}
	}
}
