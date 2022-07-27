// Code generated by github.com/actgardner/gogen-avro/v10. DO NOT EDIT.
/*
 * SOURCES:
 *     orig_signing_result.avsc
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

func writeArrayOriginalSigningResult(r []OriginalSigningResult, w io.Writer) error {
	err := vm.WriteLong(int64(len(r)), w)
	if err != nil || len(r) == 0 {
		return err
	}
	for _, e := range r {
		err = writeOriginalSigningResult(e, w)
		if err != nil {
			return err
		}
	}
	return vm.WriteLong(0, w)
}

type ArrayOriginalSigningResultWrapper struct {
	Target *[]OriginalSigningResult
}

func (_ ArrayOriginalSigningResultWrapper) SetBoolean(v bool)     { panic("Unsupported operation") }
func (_ ArrayOriginalSigningResultWrapper) SetInt(v int32)        { panic("Unsupported operation") }
func (_ ArrayOriginalSigningResultWrapper) SetLong(v int64)       { panic("Unsupported operation") }
func (_ ArrayOriginalSigningResultWrapper) SetFloat(v float32)    { panic("Unsupported operation") }
func (_ ArrayOriginalSigningResultWrapper) SetDouble(v float64)   { panic("Unsupported operation") }
func (_ ArrayOriginalSigningResultWrapper) SetBytes(v []byte)     { panic("Unsupported operation") }
func (_ ArrayOriginalSigningResultWrapper) SetString(v string)    { panic("Unsupported operation") }
func (_ ArrayOriginalSigningResultWrapper) SetUnionElem(v int64)  { panic("Unsupported operation") }
func (_ ArrayOriginalSigningResultWrapper) Get(i int) types.Field { panic("Unsupported operation") }
func (_ ArrayOriginalSigningResultWrapper) AppendMap(key string) types.Field {
	panic("Unsupported operation")
}
func (_ ArrayOriginalSigningResultWrapper) Finalize()        {}
func (_ ArrayOriginalSigningResultWrapper) SetDefault(i int) { panic("Unsupported operation") }
func (r ArrayOriginalSigningResultWrapper) HintSize(s int) {
	if len(*r.Target) == 0 {
		*r.Target = make([]OriginalSigningResult, 0, s)
	}
}
func (r ArrayOriginalSigningResultWrapper) NullField(i int) {
	panic("Unsupported operation")
}

func (r ArrayOriginalSigningResultWrapper) AppendArray() types.Field {
	var v OriginalSigningResult
	v = NewOriginalSigningResult()

	*r.Target = append(*r.Target, v)
	return &types.Record{Target: &(*r.Target)[len(*r.Target)-1]}
}
