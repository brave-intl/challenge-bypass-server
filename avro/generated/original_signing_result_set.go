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
	"encoding/json"
	"fmt"
	"io"

	"github.com/actgardner/gogen-avro/v10/compiler"
	"github.com/actgardner/gogen-avro/v10/vm"
	"github.com/actgardner/gogen-avro/v10/vm/types"
)

var _ = fmt.Printf

// Top level request containing the data to be processed, as well as any top level metadata for this message.
type OriginalSigningResultSet struct {
	Request_id string `json:"request_id"`

	Data []OriginalSigningResult `json:"data"`
}

const OriginalSigningResultSetAvroCRC64Fingerprint = "\\U*\x8e\xb6\xf8\xd0\x10"

func NewOriginalSigningResultSet() OriginalSigningResultSet {
	r := OriginalSigningResultSet{}
	r.Data = make([]OriginalSigningResult, 0)

	return r
}

func DeserializeOriginalSigningResultSet(r io.Reader) (OriginalSigningResultSet, error) {
	t := NewOriginalSigningResultSet()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func DeserializeOriginalSigningResultSetFromSchema(r io.Reader, schema string) (OriginalSigningResultSet, error) {
	t := NewOriginalSigningResultSet()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func writeOriginalSigningResultSet(r OriginalSigningResultSet, w io.Writer) error {
	var err error
	err = vm.WriteString(r.Request_id, w)
	if err != nil {
		return err
	}
	err = writeArrayOriginalSigningResult(r.Data, w)
	if err != nil {
		return err
	}
	return err
}

func (r OriginalSigningResultSet) Serialize(w io.Writer) error {
	return writeOriginalSigningResultSet(r, w)
}

func (r OriginalSigningResultSet) Schema() string {
	return "{\"doc\":\"Top level request containing the data to be processed, as well as any top level metadata for this message.\",\"fields\":[{\"name\":\"request_id\",\"type\":\"string\"},{\"name\":\"data\",\"type\":{\"items\":{\"fields\":[{\"name\":\"signed_tokens\",\"type\":{\"items\":{\"name\":\"signed_token\",\"type\":\"string\"},\"type\":\"array\"}},{\"name\":\"public_key\",\"type\":\"string\"},{\"name\":\"proof\",\"type\":\"string\"},{\"name\":\"status\",\"type\":{\"name\":\"OriginalSigningResultStatus\",\"symbols\":[\"ok\",\"invalid_issuer\",\"error\"],\"type\":\"enum\"}},{\"doc\":\"contains METADATA\",\"name\":\"associated_data\",\"type\":\"bytes\"}],\"name\":\"OriginalSigningResult\",\"namespace\":\"brave.cbp\",\"type\":\"record\"},\"type\":\"array\"}}],\"name\":\"brave.cbp.OriginalSigningResultSet\",\"type\":\"record\"}"
}

func (r OriginalSigningResultSet) SchemaName() string {
	return "brave.cbp.OriginalSigningResultSet"
}

func (_ OriginalSigningResultSet) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) SetInt(v int32)       { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) SetLong(v int64)      { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) SetString(v string)   { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *OriginalSigningResultSet) Get(i int) types.Field {
	switch i {
	case 0:
		w := types.String{Target: &r.Request_id}

		return w

	case 1:
		r.Data = make([]OriginalSigningResult, 0)

		w := ArrayOriginalSigningResultWrapper{Target: &r.Data}

		return w

	}
	panic("Unknown field index")
}

func (r *OriginalSigningResultSet) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *OriginalSigningResultSet) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ OriginalSigningResultSet) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) HintSize(int)                     { panic("Unsupported operation") }
func (_ OriginalSigningResultSet) Finalize()                        {}

func (_ OriginalSigningResultSet) AvroCRC64Fingerprint() []byte {
	return []byte(OriginalSigningResultSetAvroCRC64Fingerprint)
}

func (r OriginalSigningResultSet) MarshalJSON() ([]byte, error) {
	var err error
	output := make(map[string]json.RawMessage)
	output["request_id"], err = json.Marshal(r.Request_id)
	if err != nil {
		return nil, err
	}
	output["data"], err = json.Marshal(r.Data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(output)
}

func (r *OriginalSigningResultSet) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	var val json.RawMessage
	val = func() json.RawMessage {
		if v, ok := fields["request_id"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Request_id); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for request_id")
	}
	val = func() json.RawMessage {
		if v, ok := fields["data"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Data); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for data")
	}
	return nil
}
