// Code generated by github.com/actgardner/gogen-avro/v10. DO NOT EDIT.
/*
 * SOURCES:
 *     redeem_request.avsc
 *     redeem_result.avsc
 *     signing_request.avsc
 *     signing_result.avsc
 */
package generated

import (
	"io"

	"github.com/actgardner/gogen-avro/v10/compiler"
	"github.com/actgardner/gogen-avro/v10/container"
	"github.com/actgardner/gogen-avro/v10/vm"
)

func NewSigningResultWriter(writer io.Writer, codec container.Codec, recordsPerBlock int64) (*container.Writer, error) {
	str := NewSigningResult()
	return container.NewWriter(writer, codec, recordsPerBlock, str.Schema())
}

// container reader
type SigningResultReader struct {
	r io.Reader
	p *vm.Program
}

func NewSigningResultReader(r io.Reader) (*SigningResultReader, error) {
	containerReader, err := container.NewReader(r)
	if err != nil {
		return nil, err
	}

	t := NewSigningResult()
	deser, err := compiler.CompileSchemaBytes([]byte(containerReader.AvroContainerSchema()), []byte(t.Schema()))
	if err != nil {
		return nil, err
	}

	return &SigningResultReader{
		r: containerReader,
		p: deser,
	}, nil
}

func (r SigningResultReader) Read() (SigningResult, error) {
	t := NewSigningResult()
	err := vm.Eval(r.r, r.p, &t)
	return t, err
}