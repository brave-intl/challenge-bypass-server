// Code generated by github.com/actgardner/gogen-avro/v8. DO NOT EDIT.
/*
 * SOURCES:
 *     redeem_request.avsc
 *     redeem_result.avsc
 *     signing_request.avsc
 *     signing_result.avsc
 *     verification_request.avsc
 *     verification_result.avsc
 */
package generated

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/actgardner/gogen-avro/v9/vm"
	"github.com/actgardner/gogen-avro/v9/vm/types"
)

type SigningResultStatus int32

const (
	SigningResultStatusOk             SigningResultStatus = 0
	SigningResultStatusInvalid_issuer SigningResultStatus = 1
	SigningResultStatusError          SigningResultStatus = 2
)

func (e SigningResultStatus) String() string {
	switch e {
	case SigningResultStatusOk:
		return "ok"
	case SigningResultStatusInvalid_issuer:
		return "invalid_issuer"
	case SigningResultStatusError:
		return "error"
	}
	return "unknown"
}

func writeSigningResultStatus(r SigningResultStatus, w io.Writer) error {
	return vm.WriteInt(int32(r), w)
}

func NewSigningResultStatusValue(raw string) (r SigningResultStatus, err error) {
	switch raw {
	case "ok":
		return SigningResultStatusOk, nil
	case "invalid_issuer":
		return SigningResultStatusInvalid_issuer, nil
	case "error":
		return SigningResultStatusError, nil
	}

	return -1, fmt.Errorf("invalid value for SigningResultStatus: '%s'", raw)
}

func (b SigningResultStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.String())
}

func (b *SigningResultStatus) UnmarshalJSON(data []byte) error {
	var stringVal string
	err := json.Unmarshal(data, &stringVal)
	if err != nil {
		return err
	}
	val, err := NewSigningResultStatusValue(stringVal)
	*b = val
	return err
}

type SigningResultStatusWrapper struct {
	Target *SigningResultStatus
}

func (b *SigningResultStatusWrapper) SetBoolean(v bool) {
	panic("Unable to assign boolean to int field")
}

func (b *SigningResultStatusWrapper) SetInt(v int32) {
	*(b.Target) = SigningResultStatus(v)
}

func (b *SigningResultStatusWrapper) SetLong(v int64) {
	panic("Unable to assign long to int field")
}

func (b *SigningResultStatusWrapper) SetFloat(v float32) {
	panic("Unable to assign float to int field")
}

func (b *SigningResultStatusWrapper) SetUnionElem(v int64) {
	panic("Unable to assign union elem to int field")
}

func (b *SigningResultStatusWrapper) SetDouble(v float64) {
	panic("Unable to assign double to int field")
}

func (b *SigningResultStatusWrapper) SetBytes(v []byte) {
	panic("Unable to assign bytes to int field")
}

func (b *SigningResultStatusWrapper) SetString(v string) {
	panic("Unable to assign string to int field")
}

func (b *SigningResultStatusWrapper) Get(i int) types.Field {
	panic("Unable to get field from int field")
}

func (b *SigningResultStatusWrapper) SetDefault(i int) {
	panic("Unable to set default on int field")
}

func (b *SigningResultStatusWrapper) AppendMap(key string) types.Field {
	panic("Unable to append map key to from int field")
}

func (b *SigningResultStatusWrapper) AppendArray() types.Field {
	panic("Unable to append array element to from int field")
}

func (b *SigningResultStatusWrapper) NullField(int) {
	panic("Unable to null field in int field")
}

func (b *SigningResultStatusWrapper) Finalize() {}
