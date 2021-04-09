package procproxy

import (
	"net/http"
)

type HeaderWhitelist interface {
	Filter(headers http.Header)
	IsWhitelisted(name string) bool
	WriteFilteredTo(to http.Header, headers http.Header)
}

type headerWhitelistSet map[string]bool

func (h headerWhitelistSet) WriteFilteredTo(to http.Header, headers http.Header) {
	for name := range headers {
		ok := h.IsWhitelisted(name)
		if ok {
			// we ignore multiple headers
			to.Set(name, headers.Get(name))
		}
	}
}

func (h headerWhitelistSet) IsWhitelisted(name string) bool {
	canonized := http.CanonicalHeaderKey(name)
	return h[canonized]
}

func (h headerWhitelistSet) Filter(headers http.Header) {
	for existingHeader := range headers {
		if !h.IsWhitelisted(existingHeader) {
			headers.Del(existingHeader)
		}
	}
}

func NewHeaderWhitelist(names... string) HeaderWhitelist {
	whitelist := make(headerWhitelistSet)
	for _, value := range names {
		whitelist[http.CanonicalHeaderKey(value)] = true
	}
	return whitelist
}

var defaultRequestHeadersWhitelist = NewHeaderWhitelist(
	"referer",
	"upgrade-insecure-requests",
	"if-modified-since",
	"if-unmodified-since",
	"if-none-match",
	"if-match",
	"cache-control",
	"pragma",
)

var defaultResponseHeadersWhitelist = NewHeaderWhitelist(
	"etag",
	"expires",
	"cache-control",
	"age",
	"pragma",
	"vary",
	"last-modified",
)
