package procproxy

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type ProxyHandler struct {
	Client      http.Client
	BackendUrl  string
	ProxyAction ProxyAction
}

type ProxyResponse struct {
	Content     []byte
	ContentType string
}

type ProxyAction func(w http.ResponseWriter, action string, arguments string, upstream *http.Response) (*ProxyResponse, error)

func (c *ProxyHandler) LoadDocument(path string) (*http.Response, error) {
	var backendUrl string
	if path[0] != '/' {
		backendUrl = c.BackendUrl + "/" + path
	} else {
		backendUrl = c.BackendUrl + path
	}
	resp, err := c.Client.Get(backendUrl)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("upstream request failed: %d %s\n", resp.StatusCode, resp.Status)
	}
	return resp, nil
}

func (c *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(r.URL.Path[1:], "/", 3)
	if len(parts) != 3 || parts[2] == "" {
		log.Printf("Got %d parts\n", len(parts))
		printError(w, 404, "Invalid path")
		return
	}
	action := parts[0]
	args := parts[1]
	path := parts[2]
	response, err := c.LoadDocument(path)
	if err != nil {
		log.Println(err)
		printError(w, 500, "Failed to load upstream document")
		return
	}
	result, err := c.ProxyAction(w, action, args, response)
	if err != nil {
		log.Println(err)
		printError(w, 500, "Failed to execute action")
		return
	}
	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "script-src 'none'; default-src 'unsafe-inline'")
	w.Header().Set("Content-Length", strconv.Itoa(len(result.Content)))
	w.WriteHeader(200)
	_, _ = w.Write(result.Content)
}

func RunProxyHandler(action ProxyAction) {
	backendPtr := flag.String("backend", "", "The backend URL.")
	listenAddress := flag.String("listen", ":9090", "The listen address")
	flag.Parse()
	if *backendPtr == "" {
		log.Fatalln("No backend configured")
	}

	client := &ProxyHandler{
		Client:      http.Client{},
		BackendUrl:  *backendPtr,
		ProxyAction: action,
	}

	http.Handle("/", client)

	log.Printf("Starting to listen on '%s'\n", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}

func printError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	_, _ = fmt.Fprintf(w, "Error: %s", message)
}
