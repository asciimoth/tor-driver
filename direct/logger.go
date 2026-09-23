package direct

import (
	"fmt"
	"io"
	"log"

	tor "github.com/asciimoth/tor-driver"
)

// Log adapts the standard concurrent-safe logger. Even Fatal only logs: it
// never exits. Driver itself never calls Fatal or Fatalf.
type Log struct{ log *log.Logger }

func NewLogger(w io.Writer) *Log              { return &Log{log: log.New(w, "", log.LstdFlags)} }
func (l *Log) message(level string, v ...any) { l.log.Print(level + ": " + fmt.Sprint(v...)) }
func (l *Log) Debug(v ...any)                 { l.message("DEBUG", v...) }
func (l *Log) Debugf(f string, v ...any)      { l.message("DEBUG", fmt.Sprintf(f, v...)) }
func (l *Log) Info(v ...any)                  { l.message("INFO", v...) }
func (l *Log) Infof(f string, v ...any)       { l.message("INFO", fmt.Sprintf(f, v...)) }
func (l *Log) Warn(v ...any)                  { l.message("WARN", v...) }
func (l *Log) Warnf(f string, v ...any)       { l.message("WARN", fmt.Sprintf(f, v...)) }
func (l *Log) Err(v ...any)                   { l.message("ERROR", v...) }
func (l *Log) Errf(f string, v ...any)        { l.message("ERROR", fmt.Sprintf(f, v...)) }
func (l *Log) Fatal(v ...any)                 { l.message("FATAL", v...) }
func (l *Log) Fatalf(f string, v ...any)      { l.message("FATAL", fmt.Sprintf(f, v...)) }

var _ tor.Logger = (*Log)(nil)
