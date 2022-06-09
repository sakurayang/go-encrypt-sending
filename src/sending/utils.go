package sending

import (
	"fmt"
	"os"
	"strconv"
)

func Log(num int, v any) {
	val, ok := os.LookupEnv("DEBUG")
	if ok {
		debug, _ := strconv.ParseBool(val)
		if debug {
			fmt.Printf("[%d] %#v\n", num, v)
		}
	}
	return
}
