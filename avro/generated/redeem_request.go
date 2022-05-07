// Code generated by github.com/actgardner/gogen-avro/v8. DO NOT EDIT.
/*
 * SOURCES:
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

	"github.com/actgardner/gogen-avro/v9/compiler"
	"github.com/actgardner/gogen-avro/v9/vm"
	"github.com/actgardner/gogen-avro/v9/vm/types"
)

var _ = fmt.Printf

type RedeemRequest struct {
	// contains METADATA
	Associated_data Bytes `json:"associated_data"`

	Public_key string `json:"public_key"`

	Token_preimage string `json:"token_preimage"`

	Binding string `json:"binding"`

	Signature string `json:"signature"`
}

const RedeemRequestAvroCRC64Fingerprint = "C\xcb帹b\aC"

func NewRedeemRequest() RedeemRequest {
	r := RedeemRequest{}
	return r
}

func DeserializeRedeemRequest(r io.Reader) (RedeemRequest, error) {
	t := NewRedeemRequest()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func DeserializeRedeemRequestFromSchema(r io.Reader, schema string) (RedeemRequest, error) {
	t := NewRedeemRequest()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func writeRedeemRequest(r RedeemRequest, w io.Writer) error {
	var err error
	err = vm.WriteBytes(r.Associated_data, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Public_key, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Token_preimage, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Binding, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Signature, w)
	if err != nil {
		return err
	}
	return err
}

func (r RedeemRequest) Serialize(w io.Writer) error {
	return writeRedeemRequest(r, w)
}

func (r RedeemRequest) Schema() string {
	return "{\"fields\":[{\"doc\":\"contains METADATA\",\"name\":\"associated_data\",\"type\":\"bytes\"},{\"name\":\"public_key\",\"type\":\"string\"},{\"name\":\"token_preimage\",\"type\":\"string\"},{\"name\":\"binding\",\"type\":\"string\"},{\"name\":\"signature\",\"type\":\"string\"}],\"name\":\"brave.cbp.RedeemRequest\",\"type\":\"record\"}"
}

func (r RedeemRequest) SchemaName() string {
	return "brave.cbp.RedeemRequest"
}

func (_ RedeemRequest) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ RedeemRequest) SetInt(v int32)       { panic("Unsupported operation") }
func (_ RedeemRequest) SetLong(v int64)      { panic("Unsupported operation") }
func (_ RedeemRequest) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ RedeemRequest) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ RedeemRequest) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ RedeemRequest) SetString(v string)   { panic("Unsupported operation") }
func (_ RedeemRequest) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *RedeemRequest) Get(i int) types.Field {
	switch i {
	case 0:
		return &BytesWrapper{Target: &r.Associated_data}
	case 1:
		return &types.String{Target: &r.Public_key}
	case 2:
		return &types.String{Target: &r.Token_preimage}
	case 3:
		return &types.String{Target: &r.Binding}
	case 4:
		return &types.String{Target: &r.Signature}
	}
	panic("Unknown field index")
}

func (r *RedeemRequest) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *RedeemRequest) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ RedeemRequest) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ RedeemRequest) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ RedeemRequest) Finalize()                        {}

func (_ RedeemRequest) AvroCRC64Fingerprint() []byte {
	return []byte(RedeemRequestAvroCRC64Fingerprint)
}

func (r RedeemRequest) MarshalJSON() ([]byte, error) {
	var err error
	output := make(map[string]json.RawMessage)
	output["associated_data"], err = json.Marshal(r.Associated_data)
	if err != nil {
		return nil, err
	}
	output["public_key"], err = json.Marshal(r.Public_key)
	if err != nil {
		return nil, err
	}
	output["token_preimage"], err = json.Marshal(r.Token_preimage)
	if err != nil {
		return nil, err
	}
	output["binding"], err = json.Marshal(r.Binding)
	if err != nil {
		return nil, err
	}
	output["signature"], err = json.Marshal(r.Signature)
	if err != nil {
		return nil, err
	}
	return json.Marshal(output)
}

func (r *RedeemRequest) UnmarshalJSON(data []byte) error {
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
		if v, ok := fields["public_key"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Public_key); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for public_key")
	}
	val = func() json.RawMessage {
		if v, ok := fields["token_preimage"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Token_preimage); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for token_preimage")
	}
	val = func() json.RawMessage {
		if v, ok := fields["binding"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Binding); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for binding")
	}
	val = func() json.RawMessage {
		if v, ok := fields["signature"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Signature); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for signature")
	}
	return nil
}