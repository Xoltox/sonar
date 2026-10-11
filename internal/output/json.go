package output

import (
	"encoding/json"
	"io"

	"github.com/Xoltox/sonar/internal/scan"
)

type jsonWriter struct {
	w       io.Writer
	started bool
}

// NewJSON streams a valid JSON array, one object per line.
func NewJSON(w io.Writer) Writer {
	return &jsonWriter{w: w}
}

func (j *jsonWriter) Write(r scan.Result) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	prefix := "[\n"
	if j.started {
		prefix = ",\n"
	}
	j.started = true
	_, err = j.w.Write(append([]byte(prefix), data...))
	return err
}

func (j *jsonWriter) Close() error {
	end := "\n]\n"
	if !j.started {
		end = "[]\n"
	}
	_, err := io.WriteString(j.w, end)
	return err
}
