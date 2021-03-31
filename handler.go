package procproxy

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	defaultUserAgent = "proxproxy/1 (+github.com/coffeemakr/procproxy)"
	defaultActionName = ""
)

var (
	errNotModified = errors.New("not modified")
)

type ProxyHandler struct {
	Client      *http.Client
	Debug 		*log.Logger
	UserAgent   string
	BackendUrl  string
	ProxyAction map[string]ProxyAction
}

func (h *ProxyHandler) Handle(name string, action ProxyAction) {
	if h.ProxyAction == nil {
		h.ProxyAction = make(map[string]ProxyAction)
	}
	h.ProxyAction[name] = action
}

func (h *ProxyHandler) HandleDefault(action ProxyAction) {
	h.Handle(defaultActionName, action)
}


type ProxyResponse struct {
	Content     []byte
	ContentType string
}

type ProxyActionFnc func(arguments string, upstream *http.Response) (*ProxyResponse, error)
func (f ProxyActionFnc) Run(arguments string, upstream *http.Response) (*ProxyResponse, error) {
	return f(arguments, upstream)
}

type ProxyAction interface {
	Run(arguments string, upstream *http.Response) (*ProxyResponse, error)
}

func (h *ProxyHandler) log(format string, values ...interface{}) {
	if h.Debug != nil {
		h.Debug.Printf(format, values...)
	}
}

func (h *ProxyHandler) LoadDocument(path string, etag string) (*http.Response, error) {
	if h.BackendUrl[len(h.BackendUrl) - 1] != '/' {
		path = "/" + path
	}
	backendUrl := h.BackendUrl + path
	var client *http.Client

	if h.Client != nil {
		client = h.Client
	} else {
		client = http.DefaultClient
	}
	request, err := http.NewRequest(http.MethodGet, backendUrl, nil)
	if err != nil {
		return nil, err
	}
	var userAgent string
	if h.UserAgent == "" {
		userAgent = defaultUserAgent
	} else {
		userAgent = h.UserAgent
	}
	request.Header.Set("User-Agent", userAgent)
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	h.log("loading URL: %s", backendUrl)
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("upstream request failed: %d %s\n", resp.StatusCode, resp.Status)
	}
	return resp, nil
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	path := r.URL.EscapedPath()
	h.log("got path %s", path)
	parts := strings.SplitN(path[1:], "/", 3)
	if len(parts) != 3 {
		h.log("Did not get 3 parts: %d parts\n", len(parts))
		printError(w, 404, "Invalid path", nil)
		return
	}
	actionName := parts[0]
	args := parts[1]
	requestEtag := r.Header.Get("etag")
	var upstreamEtag string
	var currentEtag string

	currentArgsEtag, err := calcArgumentsEtag(args)
	if err != nil {
		h.log("failed to calculate arguments etag %s", err)
	} else if currentArgsEtag == currentEtag {
		h.log("etag matches current arguments")
	} else {
		h.log("etag doesnt match current arguments: %s != %s", currentEtag, currentArgsEtag)
		upstreamEtag = ""
	}
	if requestEtag != "" {
		currentEtag, upstreamEtag, err = splitEtag(requestEtag)
		if err != nil {
			h.log("cant use etag: %s", err)
		}
	}
	response, err := h.LoadDocument(parts[2], upstreamEtag)
	if err == errNotModified {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if err != nil {
		h.log("document load error: %s", err)
		printError(w, http.StatusBadGateway, "Failed to load upstream document", err)
		return
	}

	if h.ProxyAction == nil {
		printError(w, http.StatusInternalServerError, "no action configured", err)
		return
	}
	upstreamEtag = response.Header.Get("etag")
	action := h.ProxyAction[actionName]
	if action == nil {
		action = h.ProxyAction[defaultActionName]
		if action == nil {
			printError(w, http.StatusNotFound, "action doesnt exist", err)
			return
		}
	}
	result, err := action.Run(args, response)
	if err != nil {
		printError(w, http.StatusInternalServerError, "Failed to execute action", err)
		return
	}
	etag, err := joinEtag(currentArgsEtag, upstreamEtag)
	if err != nil {
		h.log("can't generate etag: %s", err)
	} else {
		h.log("setting etag %s", etag)
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "public, max-age=2592000")
	}
	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "script-src 'none'; object-src 'none'; default-src 'unsafe-inline'")
	w.Header().Set("Content-Length", strconv.Itoa(len(result.Content)))
	w.WriteHeader(200)
	_, _ = w.Write(result.Content)
}

func (h *ProxyHandler) RunFromCommandLine() {
	backendPtr := flag.String("backend", "", "The backend URL.")
	listenAddress := flag.String("listen", ":9090", "The listen address")
	debug := flag.Bool("verbose", false, "Print verbose output")
	flag.Parse()
	if *backendPtr == "" {
		log.Fatalln("No backend configured")
	}

	h.BackendUrl = *backendPtr

	if *debug {
		h.Debug = log.New(os.Stderr, "", log.Ldate | log.Ltime)
	}

	http.Handle("/", h)

	log.Printf("Starting to listen on '%s'\n", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}

func printError(w http.ResponseWriter, defaultStatusCode int, defaultMessage string, err error) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	if httpError, ok := err.(HttpError); ok {
		defaultStatusCode = httpError.StatusCode()
		defaultMessage = httpError.ErrorMessage()
	}
	w.WriteHeader(defaultStatusCode)
	_, _ = fmt.Fprintf(w, "Error: %s\n", defaultMessage)
}
