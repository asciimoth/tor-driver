//go:build !windows

package tordriver

func retryableFileReadError(error) bool { return false }
