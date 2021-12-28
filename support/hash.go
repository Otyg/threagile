package support

import (
	"fmt"
	"hash/fnv"
)

func Hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprintf("%v", h.Sum32())
}
