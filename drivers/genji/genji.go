// Package genji defines and registers usql's Genji driver.
//
// Group: bad
// See: https://github.com/genjidb/genji
package genji

import (
	_ "github.com/genjidb/genji/driver" // DRIVER
	"github.com/ildus/usql/drivers"
)

func init() {
	drivers.Register("genji", drivers.Driver{})
}
