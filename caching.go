package procproxy

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"log"
	"net/url"
	"sort"
	"strings"
)

const etagSeperator = "-"

func extractEtagContent(etag string) (string, error) {
	if strings.HasPrefix(etag, "W/") {
		return "", errors.New("weak validator found")
	}
	if etag[0] != '"' || etag[len(etag) -1] != '"' {
		return "", errors.New("invalid etag")
	}
	return etag[1:len(etag)-1], nil
}

func splitEtag(etag string) (current string, upstream string, err error){
	etag, err = extractEtagContent(etag)
	if err != nil {
		return
	}
	parts := strings.SplitN(etag, etagSeperator, 2)
	if len(parts) != 2 {
		err = errors.New("invalid etag")
	} else {
		current = parts[0]
		upstream = "\"" + parts[1] + "\""
	}
	return
}

func joinEtag(current string, upstream string) (string, error) {
	var err error
	upstream, err = extractEtagContent(upstream)
	if err != nil {
		return "", err
	}
	return "\"" + current + etagSeperator + upstream + "\"", nil
}

func calcArgumentsEtag(arguments string) (string, error){
	normalizedQuery := new(bytes.Buffer)
	values, err := url.ParseQuery(arguments)
	if err != nil {
		return "", nil
	}
	keys := make([]string, len(values))

	i := 0
	for key := range values {
		keys[i] = key
		i++
	}
	sort.Strings(keys)
	for _, key := range keys {
		keyValues := values[key]
		for _, value := range keyValues {
			normalizedQuery.WriteString(key)
			normalizedQuery.WriteRune('=')
			normalizedQuery.WriteString(url.QueryEscape(value))
			normalizedQuery.WriteRune('&')
		}
	}
	log.Printf("Normalized arguments: %s", string(normalizedQuery.Bytes()))
	hash := md5.New()
	return base64.URLEncoding.EncodeToString(hash.Sum(normalizedQuery.Bytes()))[16:], nil
}
