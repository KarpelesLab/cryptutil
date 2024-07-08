package cryptutil

import "errors"

var (
	ErrNoAppropriateKey = errors.New("no appropriate key available to open bottle")
)
