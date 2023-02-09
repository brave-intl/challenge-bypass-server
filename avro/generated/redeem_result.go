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
	"encoding/json"
	"fmt"
	"io"

	"github.com/actgardner/gogen-avro/v10/compiler"
	"github.com/actgardner/gogen-avro/v10/vm"
	"github.com/actgardner/gogen-avro/v10/vm/types"
)

var _ = fmt.Printf

type RedeemResult struct {
	Issuer_name string `json:"issuer_name"`

	Issuer_cohort int32 `json:"issuer_cohort"`

	Status RedeemResultStatus `json:"status"`
	// contains METADATA
	Associated_data Bytes `json:"associated_data"`
}

const RedeemResultAvroCRC64Fingerprint = "\x11T\xa5\xba@д;"

func NewRedeemResult() RedeemResult {
	r := RedeemResult{}
	return r
}

func DeserializeRedeemResult(r io.Reader) (RedeemResult, error) {
	t := NewRedeemResult()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func DeserializeRedeemResultFromSchema(r io.Reader, schema string) (RedeemResult, error) {
	t := NewRedeemResult()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func writeRedeemResult(r RedeemResult, w io.Writer) error {
	var err error
	err = vm.WriteString(r.Issuer_name, w)
	if err != nil {
		return err
	}
	err = vm.WriteInt(r.Issuer_cohort, w)
	if err != nil {
		return err
	}
	err = writeRedeemResultStatus(r.Status, w)
	if err != nil {
		return err
	}
	err = vm.WriteBytes(r.Associated_data, w)
	if err != nil {
		return err
	}
	return err
}

func (r RedeemResult) Serialize(w io.Writer) error {
	return writeRedeemResult(r, w)
}

func (r RedeemResult) Schema() string {
	return "{\"fields\":[{\"name\":\"issuer_name\",\"type\":\"string\"},{\"name\":\"issuer_cohort\",\"type\":\"int\"},{\"name\":\"status\",\"type\":{\"name\":\"RedeemResultStatus\",\"symbols\":[\"ok\",\"duplicate_redemption\",\"unverified\",\"error\",\"idempotent_redemption\"],\"type\":\"enum\"}},{\"doc\":\"contains METADATA\",\"name\":\"associated_data\",\"type\":\"bytes\"}],\"name\":\"brave.cbp.RedeemResult\",\"type\":\"record\"}"
}

func (r RedeemResult) SchemaName() string {
	return "brave.cbp.RedeemResult"
}

func (_ RedeemResult) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ RedeemResult) SetInt(v int32)       { panic("Unsupported operation") }
func (_ RedeemResult) SetLong(v int64)      { panic("Unsupported operation") }
func (_ RedeemResult) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ RedeemResult) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ RedeemResult) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ RedeemResult) SetString(v string)   { panic("Unsupported operation") }
func (_ RedeemResult) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *RedeemResult) Get(i int) types.Field {
	switch i {
	case 0:
		w := types.String{Target: &r.Issuer_name}

		return w

	case 1:
		w := types.Int{Target: &r.Issuer_cohort}

		return w

	case 2:
		w := RedeemResultStatusWrapper{Target: &r.Status}

		return w

	case 3:
		w := BytesWrapper{Target: &r.Associated_data}

		return w

	}
	panic("Unknown field index")
}

func (r *RedeemResult) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *RedeemResult) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ RedeemResult) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ RedeemResult) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ RedeemResult) HintSize(int)                     { panic("Unsupported operation") }
func (_ RedeemResult) Finalize()                        {}

func (_ RedeemResult) AvroCRC64Fingerprint() []byte {
	return []byte(RedeemResultAvroCRC64Fingerprint)
}

func (r RedeemResult) MarshalJSON() ([]byte, error) {
	var err error
	output := make(map[string]json.RawMessage)
	output["issuer_name"], err = json.Marshal(r.Issuer_name)
	if err != nil {
		return nil, err
	}
	output["issuer_cohort"], err = json.Marshal(r.Issuer_cohort)
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

func (r *RedeemResult) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	var val json.RawMessage
	val = func() json.RawMessage {
		if v, ok := fields["issuer_name"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Issuer_name); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for issuer_name")
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
