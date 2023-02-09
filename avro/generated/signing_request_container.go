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

	"github.com/actgardner/gogen-avro/v10/compiler"
	"github.com/actgardner/gogen-avro/v10/container"
	"github.com/actgardner/gogen-avro/v10/vm"
)

func NewSigningRequestWriter(writer io.Writer, codec container.Codec, recordsPerBlock int64) (*container.Writer, error) {
	str := NewSigningRequest()
	return container.NewWriter(writer, codec, recordsPerBlock, str.Schema())
}

// container reader
type SigningRequestReader struct {
	r io.Reader
	p *vm.Program
}

func NewSigningRequestReader(r io.Reader) (*SigningRequestReader, error) {
	containerReader, err := container.NewReader(r)
	if err != nil {
		return nil, err
	}

	t := NewSigningRequest()
	deser, err := compiler.CompileSchemaBytes([]byte(containerReader.AvroContainerSchema()), []byte(t.Schema()))
	if err != nil {
		return nil, err
	}

	return &SigningRequestReader{
		r: containerReader,
		p: deser,
	}, nil
}

func (r SigningRequestReader) Read() (SigningRequest, error) {
	t := NewSigningRequest()
	err := vm.Eval(r.r, r.p, &t)
	return t, err
}
