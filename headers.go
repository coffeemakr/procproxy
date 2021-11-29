package procproxy

import (
	"net/http"
)

type HeaderFilter interface {
	Passes(name string) bool
}

type booleanHeaderFilter bool

func (b booleanHeaderFilter) Passes(_ string) bool {
	return bool(b)
}

var AllowAllHeaders HeaderFilter = booleanHeaderFilter(true)

func CopyHeaders(to http.Header, from http.Header) {
	CopyAllowedHeadersTo(AllowAllHeaders.Passes, to, from)
}

func CopyAllowedHeadersTo(nameFilter func(string) bool, to http.Header, from http.Header) {
	if from == nil {
		return
	}
	// Find total number of values.
	totalNumberOfValues := 0
	for k, vv := range from {
		if nameFilter(k) {
			totalNumberOfValues += len(vv)
		}
	}
	sv := make([]string, totalNumberOfValues) // shared backing array for headers' values
	for k, vv := range from {
		if nameFilter(k) {
			n := copy(sv, vv)
			to[k] = sv[:n:n]
			sv = sv[n:]
		}
	}
}

func FilterAllowedHeaders(f HeaderFilter, headers http.Header) {
	for name := range headers {
		if !f.Passes(name) {
			headers.Del(name)
		}
	}
}

type headerAllowList map[string]bool

func (h headerAllowList) Passes(name string) bool {
	canonized := http.CanonicalHeaderKey(name)
	return h[canonized]
}

type headerBlocklist map[string]bool

func (h headerBlocklist) Passes(name string) bool {
	canonized := http.CanonicalHeaderKey(name)
	return !h[canonized]
}

func NewHeaderAllowList(names ...string) HeaderFilter {
	filter := make(headerAllowList)
	for _, value := range names {
		filter[http.CanonicalHeaderKey(value)] = true
	}
	return filter
}

func NewHeaderBlockList(names ...string) HeaderFilter {
	filter := make(headerBlocklist)
	for _, value := range names {
		filter[http.CanonicalHeaderKey(value)] = true
	}
	return filter
}

// The HopByHopHeaderFilter blocks headers according to
// https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1
var HopByHopHeaderFilter = NewHeaderBlockList(
	"connection",
	"keep-alive",
	"proxy-authenticate",
	"proxy-authorization",
	"te",
	"trailers",
	"transfer-encoding",
	"upgrade",
	// other headers that are not used end-to-end because we decode and re-encode the content
	"range",
	"accept-ranges",
	"content-encoding",
	"accept-encoding",
)
