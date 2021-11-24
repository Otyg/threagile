package support

import (
	"path/filepath"
	"strings"
)

func GetLinkFromMarkdownAsHtml(link string) string {
	urlAndCaption := strings.Split(link, "](")
	if len(urlAndCaption) > 1 {
		return "<a href=\"" + strings.ReplaceAll(urlAndCaption[1], ")", "") + "\">" + strings.ReplaceAll(urlAndCaption[0], "[", "") + "</a>"
	} else if strings.HasPrefix(link, "http") {
		lastLinkParts := strings.Split(link, "/")
		steps := 1
		if strings.HasPrefix(link, "/") {
			steps = 2
		}
		linkText := lastLinkParts[len(lastLinkParts)-steps]
		if strings.HasSuffix(linkText, ".html") || strings.HasSuffix(linkText, ".htm") {
			var extension = filepath.Ext(linkText)
			linkText = linkText[0 : len(linkText)-len(extension)]
		}
		return "<a href=\"" + link + "\">" + linkText + "</a>"
	}
	return link
}
