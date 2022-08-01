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

func writeArraySigningResultV2(r []SigningResultV2, w io.Writer) error {
	err := vm.WriteLong(int64(len(r)), w)
	if err != nil || len(r) == 0 {
		return err
	}
	for _, e := range r {
		err = writeSigningResultV2(e, w)
		if err != nil {
			return err
		}
	}
	return vm.WriteLong(0, w)
}

type ArraySigningResultV2Wrapper struct {
	Target *[]SigningResultV2
}

func (_ ArraySigningResultV2Wrapper) SetBoolean(v bool)     { panic("Unsupported operation") }
func (_ ArraySigningResultV2Wrapper) SetInt(v int32)        { panic("Unsupported operation") }
func (_ ArraySigningResultV2Wrapper) SetLong(v int64)       { panic("Unsupported operation") }
func (_ ArraySigningResultV2Wrapper) SetFloat(v float32)    { panic("Unsupported operation") }
func (_ ArraySigningResultV2Wrapper) SetDouble(v float64)   { panic("Unsupported operation") }
func (_ ArraySigningResultV2Wrapper) SetBytes(v []byte)     { panic("Unsupported operation") }
func (_ ArraySigningResultV2Wrapper) SetString(v string)    { panic("Unsupported operation") }
func (_ ArraySigningResultV2Wrapper) SetUnionElem(v int64)  { panic("Unsupported operation") }
func (_ ArraySigningResultV2Wrapper) Get(i int) types.Field { panic("Unsupported operation") }
func (_ ArraySigningResultV2Wrapper) AppendMap(key string) types.Field {
	panic("Unsupported operation")
}
func (_ ArraySigningResultV2Wrapper) Finalize()        {}
func (_ ArraySigningResultV2Wrapper) SetDefault(i int) { panic("Unsupported operation") }
func (r ArraySigningResultV2Wrapper) HintSize(s int) {
	if len(*r.Target) == 0 {
		*r.Target = make([]SigningResultV2, 0, s)
	}
}
func (r ArraySigningResultV2Wrapper) NullField(i int) {
	panic("Unsupported operation")
}

func (r ArraySigningResultV2Wrapper) AppendArray() types.Field {
	var v SigningResultV2
	v = NewSigningResultV2()

	*r.Target = append(*r.Target, v)
	return &types.Record{Target: &(*r.Target)[len(*r.Target)-1]}
}