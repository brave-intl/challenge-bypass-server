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

type SigningRequest struct {
	// contains METADATA
	Associated_data Bytes `json:"associated_data"`

	Blinded_tokens []string `json:"blinded_tokens"`

	Issuer_type string `json:"issuer_type"`

	Issuer_cohort int32 `json:"issuer_cohort"`
}

const SigningRequestAvroCRC64Fingerprint = "\x8a\xfc\xfb\xa4\xcf\xfea\x06"

func NewSigningRequest() SigningRequest {
	r := SigningRequest{}
	r.Blinded_tokens = make([]string, 0)

	return r
}

func DeserializeSigningRequest(r io.Reader) (SigningRequest, error) {
	t := NewSigningRequest()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func DeserializeSigningRequestFromSchema(r io.Reader, schema string) (SigningRequest, error) {
	t := NewSigningRequest()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func writeSigningRequest(r SigningRequest, w io.Writer) error {
	var err error
	err = vm.WriteBytes(r.Associated_data, w)
	if err != nil {
		return err
	}
	err = writeArrayString(r.Blinded_tokens, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Issuer_type, w)
	if err != nil {
		return err
	}
	err = vm.WriteInt(r.Issuer_cohort, w)
	if err != nil {
		return err
	}
	return err
}

func (r SigningRequest) Serialize(w io.Writer) error {
	return writeSigningRequest(r, w)
}

func (r SigningRequest) Schema() string {
	return "{\"fields\":[{\"doc\":\"contains METADATA\",\"name\":\"associated_data\",\"type\":\"bytes\"},{\"name\":\"blinded_tokens\",\"type\":{\"items\":{\"name\":\"blinded_token\",\"namespace\":\"brave.cbp\",\"type\":\"string\"},\"type\":\"array\"}},{\"name\":\"issuer_type\",\"type\":\"string\"},{\"name\":\"issuer_cohort\",\"type\":\"int\"}],\"name\":\"brave.cbp.SigningRequest\",\"type\":\"record\"}"
}

func (r SigningRequest) SchemaName() string {
	return "brave.cbp.SigningRequest"
}

func (_ SigningRequest) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ SigningRequest) SetInt(v int32)       { panic("Unsupported operation") }
func (_ SigningRequest) SetLong(v int64)      { panic("Unsupported operation") }
func (_ SigningRequest) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ SigningRequest) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ SigningRequest) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ SigningRequest) SetString(v string)   { panic("Unsupported operation") }
func (_ SigningRequest) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *SigningRequest) Get(i int) types.Field {
	switch i {
	case 0:
		w := BytesWrapper{Target: &r.Associated_data}

		return w

	case 1:
		r.Blinded_tokens = make([]string, 0)

		w := ArrayStringWrapper{Target: &r.Blinded_tokens}

		return w

	case 2:
		w := types.String{Target: &r.Issuer_type}

		return w

	case 3:
		w := types.Int{Target: &r.Issuer_cohort}

		return w

	}
	panic("Unknown field index")
}

func (r *SigningRequest) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *SigningRequest) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ SigningRequest) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ SigningRequest) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ SigningRequest) HintSize(int)                     { panic("Unsupported operation") }
func (_ SigningRequest) Finalize()                        {}

func (_ SigningRequest) AvroCRC64Fingerprint() []byte {
	return []byte(SigningRequestAvroCRC64Fingerprint)
}

func (r SigningRequest) MarshalJSON() ([]byte, error) {
	var err error
	output := make(map[string]json.RawMessage)
	output["associated_data"], err = json.Marshal(r.Associated_data)
	if err != nil {
		return nil, err
	}
	output["blinded_tokens"], err = json.Marshal(r.Blinded_tokens)
	if err != nil {
		return nil, err
	}
	output["issuer_type"], err = json.Marshal(r.Issuer_type)
	if err != nil {
		return nil, err
	}
	output["issuer_cohort"], err = json.Marshal(r.Issuer_cohort)
	if err != nil {
		return nil, err
	}
	return json.Marshal(output)
}

func (r *SigningRequest) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	var val json.RawMessage
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
	val = func() json.RawMessage {
		if v, ok := fields["blinded_tokens"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Blinded_tokens); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for blinded_tokens")
	}
	val = func() json.RawMessage {
		if v, ok := fields["issuer_type"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Issuer_type); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for issuer_type")
	}
	val = func() json.RawMessage {
		if v, ok := fields["issuer_cohort"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Issuer_cohort); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for issuer_cohort")
	}
	return nil
}
