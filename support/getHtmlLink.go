package support

import (
	"path/filepath"
	"strings"
)

func GetHtmlLink(link string) string {
	urlAndCaption := strings.Split(link, "](")
	if len(urlAndCaption) > 1 {
		return "<a href=\"" + strings.ReplaceAll(urlAndCaption[1], ")", "") + "\">" + strings.ReplaceAll(urlAndCaption[0], "[", "") + "</a>"
	} else if strings.HasPrefix(link, "http") {
		lastLinkParts := strings.Split(link, "/")
		steps := 1
		if strings.HasSuffix(link, "/") {
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

func GetLinkText(link string) string {
	urlAndCaption := strings.Split(link, "](")
	if len(urlAndCaption) > 1 {
		return strings.ReplaceAll(urlAndCaption[0], "[", "")
	} else if strings.HasPrefix(link, "http") {
		lastLinkParts := strings.Split(link, "/")
		steps := 1
		if strings.HasSuffix(link, "/") {
			steps = 2
		}
		linkText := lastLinkParts[len(lastLinkParts)-steps]
		if strings.HasSuffix(linkText, ".html") || strings.HasSuffix(linkText, ".htm") {
			var extension = filepath.Ext(linkText)
			linkText = linkText[0 : len(linkText)-len(extension)]
		}
		return linkText
	}
	return link
}
func GetLinkUrl(link string) string {
	urlAndCaption := strings.Split(link, "](")
	if len(urlAndCaption) > 1 {
		return strings.ReplaceAll(urlAndCaption[1], ")", "")
	}
	return link
}
