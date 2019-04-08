package monitor

import "testing"

func Test_containsDomain(t *testing.T) {
	tests := []struct {
		name   string
		l      []string
		domain string
		result bool
	}{
		{
			name:   "simple domain",
			l:      []string{"foo.com"},
			domain: "foo.com",
			result: true,
		},
		{
			name:   "simple domain does not match subdomain",
			l:      []string{"foo.com"},
			domain: "bar.foo.com",
			result: false,
		},
		{
			name:   "regex matches subdomain",
			l:      []string{`/\.foo\.com$/`},
			domain: "bar.foo.com",
			result: true,
		},
		{
			name:   "evaulates mix of regexes and non-regexes",
			l:      []string{"some.domain.com", `/\.foo\.com$/`},
			domain: "bar.foo.com",
			result: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsDomain(tt.l, tt.domain); got != tt.result {
				t.Errorf("containsDomain(%v, %q) = %v; want %v", tt.l, tt.domain, got, tt.result)
			}
		})
	}
}
