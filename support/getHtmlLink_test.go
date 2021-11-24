package support

import (
	"testing"
)

func TestGetLinkFromMarkdownAsHtml(t *testing.T) {
	type args struct {
		link string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"markdown-style with caption", args{"[v4.2-4.9.1: Testing for Weak Transport Layer Security](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/)"}, "<a href=\"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/\">v4.2-4.9.1: Testing for Weak Transport Layer Security</a>"},
		{"no url, only text", args{"v4.2-4.9.1: Testing for Weak Transport Layer Security"}, "v4.2-4.9.1: Testing for Weak Transport Layer Security"},
		{"url", args{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/"}, "<a href=\"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/\">01-Testing_for_Weak_Transport_Layer_Security</a>"},
		{"url-no-trailing", args{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"}, "<a href=\"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security\">01-Testing_for_Weak_Transport_Layer_Security</a>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetHtmlLink(tt.args.link); got != tt.want {
				t.Errorf("GetHtmlLink() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetLinkText(t *testing.T) {
	type args struct {
		link string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"markdown-style with caption", args{"[v4.2-4.9.1: Testing for Weak Transport Layer Security](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/)"}, "v4.2-4.9.1: Testing for Weak Transport Layer Security"},
		{"no url, only text", args{"v4.2-4.9.1: Testing for Weak Transport Layer Security"}, "v4.2-4.9.1: Testing for Weak Transport Layer Security"},
		{"url", args{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/"}, "01-Testing_for_Weak_Transport_Layer_Security"},
		{"url-no-trailing", args{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"}, "01-Testing_for_Weak_Transport_Layer_Security"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetLinkText(tt.args.link); got != tt.want {
				t.Errorf("GetLinkText() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestGetLinkUrl(t *testing.T) {
	type args struct {
		link string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"markdown-style with caption", args{"[v4.2-4.9.1: Testing for Weak Transport Layer Security](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/)"}, "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/"},
		{"no url, only text", args{"v4.2-4.9.1: Testing for Weak Transport Layer Security"}, "v4.2-4.9.1: Testing for Weak Transport Layer Security"},
		{"url", args{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/"}, "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/"},
		{"url-no-trailing", args{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"}, "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetLinkUrl(tt.args.link); got != tt.want {
				t.Errorf("GetLinkUrl() = %v, want %v", got, tt.want)
			}
		})
	}
}
