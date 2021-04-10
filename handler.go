package procproxy

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	defaultUserAgent  = "proxproxy/1 (+github.com/coffeemakr/procproxy)"
	defaultActionName = ""
)

type ProxyHandler struct {
	Client             *http.Client
	Debug              *log.Logger
	UserAgent          string
	BackendUrl         string
	ProxyAction        map[string]ProxyAction
	fwdRequestHeaders  HeaderWhitelist
	fwdResponseHeaders HeaderWhitelist
}

func (h *ProxyHandler) writeForwardedResponseHeaders(writtenTo http.Header, headers http.Header) {
	var filters HeaderWhitelist
	if h.fwdResponseHeaders == nil {
		filters = defaultResponseHeadersWhitelist
	} else {
		filters = h.fwdResponseHeaders
	}
	filters.WriteFilteredTo(writtenTo, headers)
}

func (h *ProxyHandler) filterForwardedRequestHeaders(header http.Header) {
	var filters HeaderWhitelist
	if h.fwdRequestHeaders == nil {
		filters = defaultRequestHeadersWhitelist
	} else {
		filters = h.fwdRequestHeaders
	}
	filters.Filter(header)
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

var DefaultClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Get fetches a document from the backend and returns the response or an if the connection failed.
// Checking the status code and reading the content is up to the caller.
func (h *ProxyHandler) Get(path string, headers http.Header) (*http.Response, error) {
	if h.BackendUrl[len(h.BackendUrl)-1] != '/' {
		path = "/" + path
	}
	backendUrl := h.BackendUrl + path
	var client *http.Client

	if h.Client != nil {
		client = h.Client
	} else {
		client = DefaultClient
	}
	h.filterForwardedRequestHeaders(headers)
	request, err := http.NewRequest(http.MethodGet, backendUrl, nil)
	if err != nil {
		return nil, err
	}
	request.Header = headers
	var userAgent string
	if h.UserAgent == "" {
		userAgent = defaultUserAgent
	} else {
		userAgent = h.UserAgent
	}
	request.Header.Set("User-Agent", userAgent)
	h.log("loading URL: %s", backendUrl)
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
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
	if h.ProxyAction == nil {
		printError(w, http.StatusInternalServerError, "no action configured", err)
		return
	}
	action := h.ProxyAction[actionName]
	if action == nil {
		action = h.ProxyAction[defaultActionName]
		if action == nil {
			printError(w, http.StatusNotFound, "action doesnt exist", err)
			return
		}
	}

	args := parts[1]
	response, err := h.Get(parts[2], r.Header)
	if err != nil {
		h.log("document load error: %s", err)
		printError(w, http.StatusBadGateway, "error loading upstream document", err)
		return
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			h.log("error closing request body: %s", err)
		}
	}(response.Body)

	switch response.StatusCode {
	case 200:
		// ok
	case 304:
		h.writeForwardedResponseHeaders(w.Header(), response.Header)
		w.WriteHeader(response.StatusCode)
		return
	default:
		printError(w, http.StatusBadGateway, "Gateway request failed", nil)
		return
	}

	result, err := action.Run(args, response)
	if err != nil {
		h.log("action failed: %s", err)
		printError(w, http.StatusInternalServerError, "Failed to execute action", err)
		return
	}
	h.writeForwardedResponseHeaders(w.Header(), response.Header)
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
		h.Debug = log.New(os.Stderr, "", log.Ldate|log.Ltime)
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
