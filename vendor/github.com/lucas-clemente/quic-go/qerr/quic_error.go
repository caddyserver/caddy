package qerr

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

// ErrorCode can be used as a normal error without reason.
type ErrorCode uint32

func (e ErrorCode) Error() string {
	return e.String()
}

// A QuicError consists of an error code plus a error reason
type QuicError struct {
	ErrorCode    ErrorCode
	ErrorMessage string
}

// Error creates a new QuicError instance
func Error(errorCode ErrorCode, errorMessage string) *QuicError {
	return &QuicError{
		ErrorCode:    errorCode,
		ErrorMessage: errorMessage,
	}
}

func (e *QuicError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorCode.String(), e.ErrorMessage)
}

func (e *QuicError) Timeout() bool {
	switch e.ErrorCode {
	case NetworkIdleTimeout,
		HandshakeTimeout,
		TimeoutsWithOpenStreams:
		return true
	}
	return false
}

// ToQuicError converts an arbitrary error to a QuicError. It leaves QuicErrors
// unchanged, and properly handles `ErrorCode`s.
func ToQuicError(err error) *QuicError {
	switch e := err.(type) {
	case *QuicError:
		return e
	case ErrorCode:
		return Error(e, "")
	}
	utils.Errorf("Internal error: %v", err)
	return Error(InternalError, err.Error())
}
