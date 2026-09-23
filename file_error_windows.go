//go:build windows

package tordriver

import (
	"errors"

	"golang.org/x/sys/windows"
)

func retryableFileReadError(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
