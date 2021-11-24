package support

import "testing"

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
		{"url", args{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/"}, "<a href=\"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/\">01-Testing_for_Weak_Transport_Layer_Security/</a>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetLinkFromMarkdownAsHtml(tt.args.link); got != tt.want {
				t.Errorf("GetLinkFromMarkdownAsHtml() = %v, want %v", got, tt.want)
			}
		})
	}
}
