package procproxy

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	errBadRequest = UserError{
		Code:    http.StatusBadRequest,
		Message: "Bad request",
		Err:     errors.New("bad request"),
	}
)

type HttpError interface {
	StatusCode() int
	ErrorMessage() string
}

type UserError struct {
	Code int
	Message string
	Err error
}

func (e UserError) WithError(err error) *UserError {
	result := new(UserError)
	result.Message = e.Message
	result.Code = e.Code
	result.Err = err
	return result
}

func (e UserError) StatusCode() int {
	return e.Code
}

func (e UserError) ErrorMessage() string {
	return e.Message
}

type ArgumentErr struct {
	Err error
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
