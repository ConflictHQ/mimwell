package connectorsdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const MaxLine = 1 << 20
const MaxExport = 16 << 20
const MaxEvents = 1000
const MaxReceiptBytes = 1 << 20
const HostTimeout = 10 * time.Second

var orderPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,127})$`)

type payload struct {
	Encoding   string      `json:"encoding"`
	MediaType  string      `json:"mediaType"`
	ByteLength json.Number `json:"byteLength"`
	SHA256     string      `json:"sha256"`
	Data       string      `json:"data"`
}
type event struct {
	Format      string            `json:"format"`
	Namespace   string            `json:"namespace"`
	ObjectID    string            `json:"objectId"`
	EventID     string            `json:"eventId"`
	Revision    string            `json:"revision"`
	Order       json.RawMessage   `json:"order"`
	Operation   string            `json:"operation"`
	Actor       json.RawMessage   `json:"actor"`
	Thread      json.RawMessage   `json:"thread"`
	EventTime   json.RawMessage   `json:"eventTime"`
	ObservedAt  json.RawMessage   `json:"observedAt"`
	Language    json.RawMessage   `json:"language"`
	Text        json.RawMessage   `json:"text"`
	Attachments []json.RawMessage `json:"attachments"`
	Locator     string            `json:"locator"`
	Visibility  json.RawMessage   `json:"visibility"`
	Payload     payload           `json:"payload"`
}
type Event struct {
	Value   event
	Bytes   []byte
	Payload []byte
}

func ValidateJSONL(raw []byte) ([]Event, error) {
	if len(raw) > MaxExport {
		return nil, errors.New("export exceeds 16 MiB client bound")
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		return nil, errors.New("events must be LF-terminated")
	}
	lines := bytes.Split(raw, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > MaxEvents {
		return nil, errors.New("export exceeds 1000 event bound")
	}
	out := make([]Event, 0, len(lines))
	offset := 0
	for _, line := range lines {
		source := raw[offset : offset+len(line)+1]
		offset += len(line) + 1
		if len(source) > MaxLine || bytes.HasSuffix(source, []byte("\r\n")) {
			return nil, errors.New("event exceeds line bounds or uses CRLF")
		}
		if !utf8.Valid(line) {
			return nil, errors.New("event is not valid UTF-8")
		}
		if err := rejectDuplicateKeys(line); err != nil {
			return nil, err
		}
		var value event
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid event: %w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return nil, errors.New("trailing event data")
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(line, &keys); err != nil || len(keys) != 17 {
			return nil, errors.New("event fields differ from connector-event/v1")
		}
		if trimmed := bytes.TrimSpace(keys["attachments"]); len(trimmed) == 0 || trimmed[0] != '[' {
			return nil, errors.New("attachments must be an array")
		}
		var order string
		if json.Unmarshal(value.Order, &order) != nil || !orderPattern.MatchString(order) {
			return nil, errors.New("order must be a bounded decimal string")
		}
		if value.Format != "connector-event/v1" || !bounded(value.Namespace, 256, true) || !bounded(value.ObjectID, 1024, true) || !bounded(value.EventID, 1024, true) || !bounded(value.Revision, 256, true) || !bounded(value.Locator, 4096, true) {
			return nil, errors.New("invalid event identity")
		}
		for _, field := range []struct {
			raw json.RawMessage
			max int
		}{{value.Actor, 1024}, {value.Thread, 1024}, {value.EventTime, 128}, {value.ObservedAt, 128}, {value.Language, 64}, {value.Visibility, 256}} {
			if nullableString(field.raw, field.max) != nil {
				return nil, errors.New("invalid optional event metadata")
			}
		}
		if value.Operation != "upsert" && value.Operation != "edit" && value.Operation != "delete" && value.Operation != "access-change" {
			return nil, errors.New("invalid operation")
		}
		if value.Payload.Encoding != "base64" || !bounded(value.Payload.MediaType, 256, true) || len(value.Payload.Data) > 87384 {
			return nil, errors.New("invalid payload encoding")
		}
		content, err := base64.StdEncoding.DecodeString(value.Payload.Data)
		if err != nil {
			return nil, errors.New("invalid base64 payload")
		}
		n, err := value.Payload.ByteLength.Int64()
		if err != nil || n < 0 || n > 65536 || int64(len(content)) != n {
			return nil, errors.New("invalid payload length")
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != value.Payload.SHA256 || base64.StdEncoding.EncodeToString(content) != value.Payload.Data {
			return nil, errors.New("payload digest mismatch")
		}
		if value.Operation == "upsert" || value.Operation == "edit" {
			var text string
			if json.Unmarshal(value.Text, &text) != nil || !bytes.Equal(content, []byte(text)) {
				return nil, errors.New("text differs from exact payload bytes")
			}
		} else if len(content) != 0 || string(value.Text) != "null" || len(value.Attachments) != 0 {
			return nil, errors.New("control events cannot carry replacement content")
		}
		if value.Text != nil && len(value.Text) > 0 {
			var text string
			if json.Unmarshal(value.Text, &text) != nil || len([]rune(text)) > 65536 {
				return nil, errors.New("invalid event text")
			}
		}
		if len(value.Attachments) > 64 {
			return nil, errors.New("invalid event bounds")
		}
		for _, raw := range value.Attachments {
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 {
				return nil, errors.New("invalid attachment metadata")
			}
			for key, max := range map[string]int{"id": 1024, "locator": 4096, "mediaType": 256} {
				var text string
				v, ok := fields[key]
				if !ok || json.Unmarshal(v, &text) != nil || !bounded(text, max, key != "locator") {
					return nil, errors.New("invalid attachment metadata")
				}
			}
		}
		out = append(out, Event{Value: value, Bytes: append([]byte(nil), source...), Payload: content})
	}
	return out, nil
}

func bounded(value string, maximum int, nonempty bool) bool {
	return utf8.ValidString(value) && len([]rune(value)) <= maximum && (!nonempty || strings.TrimSpace(value) != "")
}
func nullableString(raw json.RawMessage, maximum int) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || !bounded(value, maximum, false) {
		return errors.New("invalid optional string")
	}
	return nil
}
func rejectDuplicateKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var readValue func() error
	readValue = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := t.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = true
				if e = readValue(); e != nil {
					return e
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := readValue(); err != nil {
		return errors.New("invalid or duplicate JSON field")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing event data")
	}
	return nil
}

func Plan(raw []byte) (map[string]any, error) {
	events, err := ValidateJSONL(raw)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{"upsert": 0, "edit": 0, "delete": 0, "access-change": 0}
	for _, item := range events {
		counts[item.Value.Operation]++
	}
	sum := sha256.Sum256(raw)
	return map[string]any{"format": "connector-client-plan/v1", "events": len(events), "operations": counts,
		"exportSha256": hex.EncodeToString(sum[:]), "authority": "host-review-required"}, nil
}

type HostClient struct {
	Python, HostScript, Root, HostConfig, Authority, Namespace, Export string
	Timeout                                                            time.Duration
}

func (c HostClient) call(args ...string) ([]byte, error) {
	return c.callInput(nil, args...)
}

func (c HostClient) callInput(input *os.File, args ...string) ([]byte, error) {
	command := []string{c.HostScript, "--root", c.Root, "--host-config", c.HostConfig, "--authority", c.Authority}
	command = append(command, args...)
	cmd := exec.Command(c.Python, command...)
	if input != nil {
		cmd.Stdin = input
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdout.Close()
		_ = stdoutWriter.Close()
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = stdoutWriter, stderrWriter
	if err = cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stdoutWriter.Close()
		_ = stderr.Close()
		_ = stderrWriter.Close()
		return nil, err
	}
	defer stdout.Close()
	defer stderr.Close()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	type capture struct {
		data     []byte
		overflow bool
		readErr  bool
	}
	drain := func(r io.Reader, ch chan<- capture) {
		data := make([]byte, 0, MaxReceiptBytes+1)
		buf := make([]byte, 65536)
		over := false
		readErr := false
		for {
			n, e := r.Read(buf)
			if n > 0 {
				room := MaxReceiptBytes + 1 - len(data)
				if room > 0 {
					take := n
					if take > room {
						take = room
					}
					data = append(data, buf[:take]...)
				}
				if len(data) > MaxReceiptBytes || n > room {
					over = true
				}
			}
			if e != nil {
				if e != io.EOF {
					readErr = true
				}
				break
			}
		}
		ch <- capture{data: data, overflow: over, readErr: readErr}
	}
	outDone, errDone := make(chan capture, 1), make(chan capture, 1)
	go drain(stdout, outDone)
	go drain(stderr, errDone)
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = HostTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var waitErr error
	var out, errout capture
	waitDone, outChannel, errChannel := wait, (<-chan capture)(outDone), (<-chan capture)(errDone)
	for waitDone != nil || outChannel != nil || errChannel != nil {
		select {
		case waitErr = <-waitDone:
			waitDone = nil
		case out = <-outChannel:
			outChannel = nil
		case errout = <-errChannel:
			errChannel = nil
		case <-timer.C:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			if waitDone != nil {
				waitErr = <-waitDone
			}
			if outChannel != nil {
				<-outChannel
			}
			if errChannel != nil {
				<-errChannel
			}
			return nil, errors.New("connector host timed out")
		}
	}
	if out.overflow || errout.overflow {
		return nil, errors.New("connector host output exceeds 1 MiB receipt bound")
	}
	if out.readErr || errout.readErr {
		return nil, errors.New("connector host output could not be read completely")
	}
	if waitErr != nil {
		return nil, errors.New("connector host failed")
	}
	return out.data, nil // Native host receipt bytes are returned unchanged.
}
func (c HostClient) Submit() ([]byte, error) {
	return c.call("--namespace", c.Namespace, "--export", c.Export)
}

// SubmitStdin inherits process stdin; only the host admits exact registered bytes.
func (c HostClient) SubmitStdin() ([]byte, error) {
	return c.callInput(os.Stdin, "--namespace", c.Namespace, "--export", c.Export, "--stdin")
}
func (c HostClient) Resume() ([]byte, error) { return c.Submit() }
func (c HostClient) Status() ([]byte, error) { return c.call("--dead-letters") }
func (c HostClient) Replay(line int) ([]byte, error) {
	if line < 1 {
		return nil, errors.New("replay line must be positive")
	}
	return c.call("--namespace", c.Namespace, "--export", c.Export, "--replay-line", fmt.Sprint(line))
}
