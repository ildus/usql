// Package voltdb defines and registers usql's VoltDB driver.
//
// See: https://github.com/VoltDB/voltdb-client-go
package voltdb

import (
	_ "github.com/VoltDB/voltdb-client-go/voltdbclient" // DRIVER
	"github.com/ildus/usql/drivers"
)

func init() {
	drivers.Register("voltdb", drivers.Driver{
		AllowMultilineComments: true,
	})
}
