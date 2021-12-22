package support

import "strings"

func Encode(value string) string {
	return strings.ReplaceAll(value, "&", "&amp;")
}
