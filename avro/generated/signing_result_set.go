// Code generated by github.com/actgardner/gogen-avro/v8. DO NOT EDIT.
/*
 * SOURCES:
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

	"github.com/actgardner/gogen-avro/v9/compiler"
	"github.com/actgardner/gogen-avro/v9/vm"
	"github.com/actgardner/gogen-avro/v9/vm/types"
)

var _ = fmt.Printf

// Top level request containing the data to be processed, as well as any top level metadata for this message.
type SigningResultSet struct {
	Request_id string `json:"request_id"`

	Data []SigningResult `json:"data"`
}

const SigningResultSetAvroCRC64Fingerprint = "\xd0:\xd2\vXk\xa6\xec"

func NewSigningResultSet() SigningResultSet {
	r := SigningResultSet{}
	r.Data = make([]SigningResult, 0)

	return r
}

func DeserializeSigningResultSet(r io.Reader) (SigningResultSet, error) {
	t := NewSigningResultSet()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func DeserializeSigningResultSetFromSchema(r io.Reader, schema string) (SigningResultSet, error) {
	t := NewSigningResultSet()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func writeSigningResultSet(r SigningResultSet, w io.Writer) error {
	var err error
	err = vm.WriteString(r.Request_id, w)
	if err != nil {
		return err
	}
	err = writeArraySigningResult(r.Data, w)
	if err != nil {
		return err
	}
	return err
}

func (r SigningResultSet) Serialize(w io.Writer) error {
	return writeSigningResultSet(r, w)
}

func (r SigningResultSet) Schema() string {
	return "{\"doc\":\"Top level request containing the data to be processed, as well as any top level metadata for this message.\",\"fields\":[{\"name\":\"request_id\",\"type\":\"string\"},{\"name\":\"data\",\"type\":{\"items\":{\"fields\":[{\"name\":\"output\",\"type\":\"bytes\"},{\"name\":\"issuer_public_key\",\"type\":\"bytes\"},{\"name\":\"status\",\"type\":{\"name\":\"SigningResultStatus\",\"symbols\":[\"ok\",\"duplicate_redemption\",\"invalid_issuer\"],\"type\":\"enum\"}},{\"doc\":\"contains METADATA\",\"name\":\"associated_data\",\"type\":\"bytes\"}],\"name\":\"SigningResult\",\"namespace\":\"brave.cbp\",\"type\":\"record\"},\"type\":\"array\"}}],\"name\":\"brave.cbp.SigningResultSet\",\"type\":\"record\"}"
}

func (r SigningResultSet) SchemaName() string {
	return "brave.cbp.SigningResultSet"
}

func (_ SigningResultSet) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ SigningResultSet) SetInt(v int32)       { panic("Unsupported operation") }
func (_ SigningResultSet) SetLong(v int64)      { panic("Unsupported operation") }
func (_ SigningResultSet) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ SigningResultSet) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ SigningResultSet) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ SigningResultSet) SetString(v string)   { panic("Unsupported operation") }
func (_ SigningResultSet) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *SigningResultSet) Get(i int) types.Field {
	switch i {
	case 0:
		return &types.String{Target: &r.Request_id}
	case 1:
		r.Data = make([]SigningResult, 0)

		return &ArraySigningResultWrapper{Target: &r.Data}
	}
	panic("Unknown field index")
}

func (r *SigningResultSet) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *SigningResultSet) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ SigningResultSet) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ SigningResultSet) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ SigningResultSet) Finalize()                        {}

func (_ SigningResultSet) AvroCRC64Fingerprint() []byte {
	return []byte(SigningResultSetAvroCRC64Fingerprint)
}

func (r SigningResultSet) MarshalJSON() ([]byte, error) {
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

func (r *SigningResultSet) UnmarshalJSON(data []byte) error {
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
