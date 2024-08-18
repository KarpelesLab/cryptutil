package cryptutil

import (
	"errors"
	"io/fs"
)

var (
	ErrNoAppropriateKey = errors.New("no appropriate key available to open bottle")
	ErrVerifyFailed     = errors.New("signature verification failed")
	ErrKeyNotFound      = wraperr("the key was not found", fs.ErrNotExist)
	ErrGroupNotFound    = wraperr("the group was not found", fs.ErrNotExist)
	ErrKeyUnfit         = errors.New("the provided key was not fit")
)

func wraperr(msg string, parent error) error {
	return &wrappedError{msg, parent}
}

type wrappedError struct {
	message string
	parent  error
}

func (e *wrappedError) Error() string {
	return e.message
}

func (e *wrappedError) Unwrap() error {
	return e.parent
}
