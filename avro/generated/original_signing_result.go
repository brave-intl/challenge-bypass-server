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

type OriginalSigningResult struct {
	Signed_tokens []string `json:"signed_tokens"`

	Issuer_public_key string `json:"issuer_public_key"`

	Proof string `json:"proof"`

	Status OriginalSigningResultStatus `json:"status"`
	// contains METADATA
	Associated_data Bytes `json:"associated_data"`
}

const OriginalSigningResultAvroCRC64Fingerprint = "\x04\x8e\x12\xbdE¸\xad"

func NewOriginalSigningResult() OriginalSigningResult {
	r := OriginalSigningResult{}
	r.Signed_tokens = make([]string, 0)

	return r
}

func DeserializeOriginalSigningResult(r io.Reader) (OriginalSigningResult, error) {
	t := NewOriginalSigningResult()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func DeserializeOriginalSigningResultFromSchema(r io.Reader, schema string) (OriginalSigningResult, error) {
	t := NewOriginalSigningResult()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func writeOriginalSigningResult(r OriginalSigningResult, w io.Writer) error {
	var err error
	err = writeArrayString(r.Signed_tokens, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Issuer_public_key, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Proof, w)
	if err != nil {
		return err
	}
	err = writeOriginalSigningResultStatus(r.Status, w)
	if err != nil {
		return err
	}
	err = vm.WriteBytes(r.Associated_data, w)
	if err != nil {
		return err
	}
	return err
}

func (r OriginalSigningResult) Serialize(w io.Writer) error {
	return writeOriginalSigningResult(r, w)
}

func (r OriginalSigningResult) Schema() string {
	return "{\"fields\":[{\"name\":\"signed_tokens\",\"type\":{\"items\":{\"name\":\"signed_token\",\"type\":\"string\"},\"type\":\"array\"}},{\"name\":\"public_key\",\"type\":\"string\"},{\"name\":\"proof\",\"type\":\"string\"},{\"name\":\"status\",\"type\":{\"name\":\"OriginalSigningResultStatus\",\"symbols\":[\"ok\",\"invalid_issuer\",\"error\"],\"type\":\"enum\"}},{\"doc\":\"contains METADATA\",\"name\":\"associated_data\",\"type\":\"bytes\"}],\"name\":\"brave.cbp.OriginalSigningResult\",\"type\":\"record\"}"
}

func (r OriginalSigningResult) SchemaName() string {
	return "brave.cbp.OriginalSigningResult"
}

func (_ OriginalSigningResult) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ OriginalSigningResult) SetInt(v int32)       { panic("Unsupported operation") }
func (_ OriginalSigningResult) SetLong(v int64)      { panic("Unsupported operation") }
func (_ OriginalSigningResult) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ OriginalSigningResult) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ OriginalSigningResult) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ OriginalSigningResult) SetString(v string)   { panic("Unsupported operation") }
func (_ OriginalSigningResult) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *OriginalSigningResult) Get(i int) types.Field {
	switch i {
	case 0:
		r.Signed_tokens = make([]string, 0)

		w := ArrayStringWrapper{Target: &r.Signed_tokens}

		return w

	case 1:
		w := types.String{Target: &r.Issuer_public_key}

		return w

	case 2:
		w := types.String{Target: &r.Proof}

		return w

	case 3:
		w := OriginalSigningResultStatusWrapper{Target: &r.Status}

		return w

	case 4:
		w := BytesWrapper{Target: &r.Associated_data}

		return w

	}
	panic("Unknown field index")
}

func (r *OriginalSigningResult) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *OriginalSigningResult) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ OriginalSigningResult) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ OriginalSigningResult) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ OriginalSigningResult) HintSize(int)                     { panic("Unsupported operation") }
func (_ OriginalSigningResult) Finalize()                        {}

func (_ OriginalSigningResult) AvroCRC64Fingerprint() []byte {
	return []byte(OriginalSigningResultAvroCRC64Fingerprint)
}

func (r OriginalSigningResult) MarshalJSON() ([]byte, error) {
	var err error
	output := make(map[string]json.RawMessage)
	output["signed_tokens"], err = json.Marshal(r.Signed_tokens)
	if err != nil {
		return nil, err
	}
	output["public_key"], err = json.Marshal(r.Issuer_public_key)
	if err != nil {
		return nil, err
	}
	output["proof"], err = json.Marshal(r.Proof)
	if err != nil {
		return nil, err
	}
	output["status"], err = json.Marshal(r.Status)
	if err != nil {
		return nil, err
	}
	output["associated_data"], err = json.Marshal(r.Associated_data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(output)
}

func (r *OriginalSigningResult) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	var val json.RawMessage
	val = func() json.RawMessage {
		if v, ok := fields["signed_tokens"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Signed_tokens); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for signed_tokens")
	}
	val = func() json.RawMessage {
		if v, ok := fields["public_key"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Issuer_public_key); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for public_key")
	}
	val = func() json.RawMessage {
		if v, ok := fields["proof"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Proof); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for proof")
	}
	val = func() json.RawMessage {
		if v, ok := fields["status"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Status); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for status")
	}
	val = func() json.RawMessage {
		if v, ok := fields["associated_data"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Associated_data); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for associated_data")
	}
	return nil
}
