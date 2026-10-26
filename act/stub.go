//go:build !act

package act

// Available reports whether ACT crypto is linked into this binary.
func Available() bool { return false }

func GenerateKey() (sk, pk []byte, err error) { return nil, nil, ErrUnavailable }

func Context(ctx []byte) ([32]byte, error) { return [32]byte{}, ErrUnavailable }

func Issue(params string, sk, req []byte, credits uint64, ctx []byte) ([]byte, error) {
	return nil, ErrUnavailable
}

func VerifySpend(params string, sk, proof []byte) (SpendInfo, error) {
	return SpendInfo{}, ErrUnavailable
}

func Refund(params string, sk, proof []byte, returned uint64) ([]byte, error) {
	return nil, ErrUnavailable
}

func ClientIssuanceRequest(params string) (pre, req []byte, err error) {
	return nil, nil, ErrUnavailable
}

func ClientFinalizeIssuance(params string, pk, pre, req, resp []byte) ([]byte, error) {
	return nil, ErrUnavailable
}

func ClientProveSpend(params string, token []byte, amount uint64) (proof, prerefund []byte, err error) {
	return nil, nil, ErrUnavailable
}

func ClientFinalizeRefund(params string, pk, prerefund, proof, refund []byte) ([]byte, error) {
	return nil, ErrUnavailable
}

func ClientBalance(token []byte) (uint64, error) { return 0, ErrUnavailable }
