package xhttp

import "fmt"

func Error(status int, message string) error {
	return httpError{
		status:  status,
		message: message,
	}
}

func AsError(err error, status int, message string) error {
	if _, ok := err.(interface{ Status() int }); ok {
		return err
	}
	return Error(status, fmt.Sprintf("%s: %s", message, err.Error()))
}

type httpError struct {
	status  int
	message string
}

func (e httpError) Status() int { return e.status }

func (e httpError) Error() string { return e.message }
