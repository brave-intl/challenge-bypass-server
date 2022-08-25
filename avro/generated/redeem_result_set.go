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

// Top level request containing the data to be processed, as well as any top level metadata for this message.
type RedeemResultSet struct {
	Request_id string `json:"request_id"`

	Data []RedeemResult `json:"data"`
}

const RedeemResultSetAvroCRC64Fingerprint = "\x04\xe6\xb5@7\xfb\xc28"

func NewRedeemResultSet() RedeemResultSet {
	r := RedeemResultSet{}
	r.Data = make([]RedeemResult, 0)

	return r
}

func DeserializeRedeemResultSet(r io.Reader) (RedeemResultSet, error) {
	t := NewRedeemResultSet()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func DeserializeRedeemResultSetFromSchema(r io.Reader, schema string) (RedeemResultSet, error) {
	t := NewRedeemResultSet()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func writeRedeemResultSet(r RedeemResultSet, w io.Writer) error {
	var err error
	err = vm.WriteString(r.Request_id, w)
	if err != nil {
		return err
	}
	err = writeArrayRedeemResult(r.Data, w)
	if err != nil {
		return err
	}
	return err
}

func (r RedeemResultSet) Serialize(w io.Writer) error {
	return writeRedeemResultSet(r, w)
}

func (r RedeemResultSet) Schema() string {
	return "{\"doc\":\"Top level request containing the data to be processed, as well as any top level metadata for this message.\",\"fields\":[{\"name\":\"request_id\",\"type\":\"string\"},{\"name\":\"data\",\"type\":{\"items\":{\"fields\":[{\"name\":\"issuer_name\",\"type\":\"string\"},{\"name\":\"issuer_cohort\",\"type\":\"int\"},{\"name\":\"status\",\"type\":{\"name\":\"RedeemResultStatus\",\"symbols\":[\"ok\",\"duplicate_redemption\",\"unverified\",\"error\",\"idempotent_redemption\"],\"type\":\"enum\"}},{\"doc\":\"contains METADATA\",\"name\":\"associated_data\",\"type\":\"bytes\"}],\"name\":\"RedeemResult\",\"namespace\":\"brave.cbp\",\"type\":\"record\"},\"type\":\"array\"}}],\"name\":\"brave.cbp.RedeemResultSet\",\"type\":\"record\"}"
}

func (r RedeemResultSet) SchemaName() string {
	return "brave.cbp.RedeemResultSet"
}

func (_ RedeemResultSet) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ RedeemResultSet) SetInt(v int32)       { panic("Unsupported operation") }
func (_ RedeemResultSet) SetLong(v int64)      { panic("Unsupported operation") }
func (_ RedeemResultSet) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ RedeemResultSet) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ RedeemResultSet) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ RedeemResultSet) SetString(v string)   { panic("Unsupported operation") }
func (_ RedeemResultSet) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *RedeemResultSet) Get(i int) types.Field {
	switch i {
	case 0:
		w := types.String{Target: &r.Request_id}

		return w

	case 1:
		r.Data = make([]RedeemResult, 0)

		w := ArrayRedeemResultWrapper{Target: &r.Data}

		return w

	}
	panic("Unknown field index")
}

func (r *RedeemResultSet) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *RedeemResultSet) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ RedeemResultSet) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ RedeemResultSet) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ RedeemResultSet) HintSize(int)                     { panic("Unsupported operation") }
func (_ RedeemResultSet) Finalize()                        {}

func (_ RedeemResultSet) AvroCRC64Fingerprint() []byte {
	return []byte(RedeemResultSetAvroCRC64Fingerprint)
}

func (r RedeemResultSet) MarshalJSON() ([]byte, error) {
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

func (r *RedeemResultSet) UnmarshalJSON(data []byte) error {
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
