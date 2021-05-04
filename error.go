package procproxy

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type ErrWithStatusCode interface {
	StatusCode() int
	error
}

type ReadableErr struct {
	Err error
}

func (r ReadableErr) ReadableError() string {
	message := r.Err.Error()
	if len(message) < 2 {
		return message
	}
	return strings.ToUpper(message[:1]) + message[1:]
}

func (r ReadableErr) Error() string {
	return r.Err.Error()
}

func (r ReadableErr) Unwrap() error {
	return r.Err
}

type ErrWithUserMessage interface {
	ReadableError() string
	error
}

type httpResponseErrorMessage struct {
	statusCode   int
	responseErrorMessage
}

func (h httpResponseErrorMessage) StatusCode() int {
	return h.statusCode
}

func (h httpResponseErrorMessage) ReadableError() string {
	return h.errorMessage
}

func (h httpResponseErrorMessage) Error() string {
	return h.err.Error()
}

type responseErrorMessage struct {
	errorMessage string
	err          error
}

func (r responseErrorMessage) ReadableError() string {
	if r.errorMessage == "" {
		return r.err.Error()
	} else {
		return r.errorMessage
	}
}

func (r responseErrorMessage) Error() string {
	return r.err.Error()
}


func newResponseErrorMessage(err error, message string) *responseErrorMessage {
	if err == nil {
		err = errors.New("no error information provided")
	}
	return &responseErrorMessage{
		errorMessage: message,
		err:          err,
	}
}
func ErrWithMessage(err error, message string) error {
	return newResponseErrorMessage(err, message)
}

func HttpError(statusCode int, message string, err error) error {
	return &httpResponseErrorMessage{
		statusCode:           statusCode,
		responseErrorMessage: *newResponseErrorMessage(err, message),
	}
}

type ArgumentErr struct {
	Err     error
	Message string
}

func (e *ArgumentErr) Error() string {
	return fmt.Sprintf("invalid arguments: %s", e.Err)
}

func (e *ArgumentErr) StatusCode() int {
	return http.StatusBadRequest
}

func (e *ArgumentErr) ErrorMessage() string {
	if e.Message != "" {
		return e.Message
	} else {
		return "invalid arguments"
	}
}

type RequestFailedErr struct {
	Response *http.Response
}

func (r RequestFailedErr) Error() string {
	return fmt.Sprintf("error loading document: %s", r.Response.Status)
}
