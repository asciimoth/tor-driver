package tordriver

// NopLogger discards all messages and never exits.
type NopLogger struct{}

func (NopLogger) Debug(...any)          {}
func (NopLogger) Debugf(string, ...any) {}
func (NopLogger) Info(...any)           {}
func (NopLogger) Infof(string, ...any)  {}
func (NopLogger) Warn(...any)           {}
func (NopLogger) Warnf(string, ...any)  {}
func (NopLogger) Err(...any)            {}
func (NopLogger) Errf(string, ...any)   {}
func (NopLogger) Fatal(...any)          {}
func (NopLogger) Fatalf(string, ...any) {}
