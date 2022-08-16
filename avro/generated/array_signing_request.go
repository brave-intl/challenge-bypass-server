// Code generated by github.com/actgardner/gogen-avro/v10. DO NOT EDIT.
/*
 * SOURCES:
 *     redeem_request.avsc
 *     redeem_result.avsc
 *     signing_request.avsc
 *     signing_result.avsc
 */
package generated

import (
	"io"

	"github.com/actgardner/gogen-avro/v10/vm"
	"github.com/actgardner/gogen-avro/v10/vm/types"
)

func writeArraySigningRequest(r []SigningRequest, w io.Writer) error {
	err := vm.WriteLong(int64(len(r)), w)
	if err != nil || len(r) == 0 {
		return err
	}
	for _, e := range r {
		err = writeSigningRequest(e, w)
		if err != nil {
			return err
		}
	}
	return vm.WriteLong(0, w)
}

type ArraySigningRequestWrapper struct {
	Target *[]SigningRequest
}

func (_ ArraySigningRequestWrapper) SetBoolean(v bool)                { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) SetInt(v int32)                   { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) SetLong(v int64)                  { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) SetFloat(v float32)               { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) SetDouble(v float64)              { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) SetBytes(v []byte)                { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) SetString(v string)               { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) SetUnionElem(v int64)             { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) Get(i int) types.Field            { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ ArraySigningRequestWrapper) Finalize()                        {}
func (_ ArraySigningRequestWrapper) SetDefault(i int)                 { panic("Unsupported operation") }
func (r ArraySigningRequestWrapper) HintSize(s int) {
	if len(*r.Target) == 0 {
		*r.Target = make([]SigningRequest, 0, s)
	}
}
func (r ArraySigningRequestWrapper) NullField(i int) {
	panic("Unsupported operation")
}

func (r ArraySigningRequestWrapper) AppendArray() types.Field {
	var v SigningRequest
	v = NewSigningRequest()

	*r.Target = append(*r.Target, v)
	return &types.Record{Target: &(*r.Target)[len(*r.Target)-1]}
}
