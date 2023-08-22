// Package ingres defines and registers usql's Ingres (Actian X, Vector, VectorH) driver.
// Requires CGO. Uses platform's Ingres libraries.
//
// See: https://github.com/ildus/ingres
// Group: base
package ingres

import (
	_ "github.com/ildus/ingres" // DRIVER
	"github.com/xo/usql/drivers"
	md "github.com/xo/usql/drivers/metadata"

	"io"
)

func init() {
	drivers.Register("ingres", drivers.Driver{
		NewMetadataReader: NewIngresReader,
		NewMetadataWriter: func(db drivers.DB, w io.Writer, opts ...md.ReaderOption) md.Writer {
			return NewIngresWriter(NewIngresReader(db, opts...))(db, w)
		},
	})
}
