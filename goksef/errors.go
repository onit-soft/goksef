package goksef

import "errors"

var (
	ErrGettingAuthChallenge   = errors.New("getting auth challenge")
	ErrAuthTokenWithSignature = errors.New("getting auth token with signature")
)
