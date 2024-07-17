package cryptutil

import "errors"

var (
	ErrNoAppropriateKey = errors.New("no appropriate key available to open bottle")
	ErrVerifyFailed     = errors.New("signature verification failed")
)
