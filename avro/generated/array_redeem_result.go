// Code generated by github.com/actgardner/gogen-avro/v10. DO NOT EDIT.
/*
 * SOURCES:
 *     redeem_request.avsc
 *     redeem_result.avsc
 *     signing_request.avsc
 *     signing_result_v1.avsc
 *     signing_result_v2.avsc
 */
package generated

import (
	"io"

	"github.com/actgardner/gogen-avro/v10/vm"
	"github.com/actgardner/gogen-avro/v10/vm/types"
)

func writeArrayRedeemResult(r []RedeemResult, w io.Writer) error {
	err := vm.WriteLong(int64(len(r)), w)
	if err != nil || len(r) == 0 {
		return err
	}
	for _, e := range r {
		err = writeRedeemResult(e, w)
		if err != nil {
			return err
		}
	}
	return vm.WriteLong(0, w)
}

type ArrayRedeemResultWrapper struct {
	Target *[]RedeemResult
}

func (_ ArrayRedeemResultWrapper) SetBoolean(v bool)                { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) SetInt(v int32)                   { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) SetLong(v int64)                  { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) SetFloat(v float32)               { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) SetDouble(v float64)              { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) SetBytes(v []byte)                { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) SetString(v string)               { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) SetUnionElem(v int64)             { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) Get(i int) types.Field            { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ ArrayRedeemResultWrapper) Finalize()                        {}
func (_ ArrayRedeemResultWrapper) SetDefault(i int)                 { panic("Unsupported operation") }
func (r ArrayRedeemResultWrapper) HintSize(s int) {
	if len(*r.Target) == 0 {
		*r.Target = make([]RedeemResult, 0, s)
	}
}
func (r ArrayRedeemResultWrapper) NullField(i int) {
	panic("Unsupported operation")
}

func (r ArrayRedeemResultWrapper) AppendArray() types.Field {
	var v RedeemResult
	v = NewRedeemResult()

	*r.Target = append(*r.Target, v)
	return &types.Record{Target: &(*r.Target)[len(*r.Target)-1]}
}
