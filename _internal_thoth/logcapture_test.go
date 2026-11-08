package thoth

import (
	"bytes"
	"log"
)

// captureLog redirects the standard logger and returns a function that restores it.
func captureLog(buf *bytes.Buffer) func() {
	previous := log.Writer()
	log.SetOutput(buf)
	return func() { log.SetOutput(previous) }
}
