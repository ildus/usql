// Package ingres defines and registers usql's Ingres (Actian X, Vector, VectorH) driver.
// Requires CGO. Uses platform's Ingres libraries.
//
// See: https://github.com/ildus/ingres
// Group: base
package ingres

import (
	_ "github.com/ildus/ingres" // DRIVER
	"github.com/ildus/usql/drivers"
	md "github.com/ildus/usql/drivers/metadata"

	"context"
	"io"
        "fmt"
)

func init() {
	drivers.Register("ingres", drivers.Driver{
		NewMetadataReader: NewIngresReader,
		NewMetadataWriter: func(db drivers.DB, w io.Writer, opts ...md.ReaderOption) md.Writer {
			return NewIngresWriter(NewIngresReader(db, opts...))(db, w)
		},
		Version: func(ctx context.Context, db drivers.DB) (string, error) {
			var out string
			err := db.QueryRowContext(ctx, `SELECT DBMSINFO('_VERSION');`).Scan(&out)
			if err != nil || out == "" {
				out = "<unknown>"
			}
			return out, nil
		},
		User: func(ctx context.Context, db drivers.DB) (string, error) {
			var out string
			err := db.QueryRowContext(ctx, `SELECT DBMSINFO('username');`).Scan(&out)
			if err != nil || out == "" {
				out = "<unknown>"
			}
			return out, nil
		},
		ChangePassword: func(db drivers.DB, user, new, old string) (error) {
			_, err := db.Exec(fmt.Sprintf(`ALTER USER %s WITH PASSWORD= '%s' `, user, new))
                        if err != nil {
                            return err
                        }
                        return nil
		},
	})
}
