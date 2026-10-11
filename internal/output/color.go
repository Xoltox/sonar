package output

import "os"

const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiGreen = "\x1b[32m"
	ansiDim   = "\x1b[2m"
)

func noColorEnv() bool {
	_, set := os.LookupEnv("NO_COLOR")
	return set
}
