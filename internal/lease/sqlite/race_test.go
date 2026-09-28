//go:build race

package sqlite

import "time"

// The race detector slows the pure Go SQLite engine by an order of
// magnitude, so a history page over the 25,000-event window needs longer
// than the production deadline. Timing tests skip under it.
const raceEnabled = true

func init() { historyDeadline = time.Minute }
