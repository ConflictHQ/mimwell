package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	sdk "conflict/mimwell/connector-sdk"
)

func main() {
	command := ""
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	flags := flag.NewFlagSet("connector-sdk "+command, flag.ExitOnError)
	file := flags.String("file", "", "operator-selected JSONL file")
	python := flags.String("python", "python3", "operator-selected Python executable")
	script := flags.String("host-script", "scripts/connector-host.py", "operator-selected local host script")
	root := flags.String("root", ".", "operator-selected brain root")
	config := flags.String("host-config", "_internal/knowledge-operations.json", "operator-selected host config")
	authority := flags.String("authority", "selected", "operator-selected authority")
	namespace := flags.String("namespace", "", "operator-selected registered namespace")
	export := flags.String("export", "", "operator-selected registered export path")
	stdin := flags.Bool("stdin", false, "observe stdin matching the exact registered export")
	line := flags.Int("line", 0, "operator-selected dead-letter line")
	timeoutMS := flags.Int("timeout-ms", 10000, "operator-selected local host deadline")
	if err := flags.Parse(os.Args[2:]); err != nil {
		fail(err)
	}
	if *timeoutMS < 1 || *timeoutMS > 300000 {
		fail(fmt.Errorf("timeout must be between 1 and 300000 ms"))
	}
	if *stdin && command != "submit" && command != "resume" {
		fail(fmt.Errorf("--stdin requires submit or resume"))
	}
	switch command {
	case "validate", "plan":
		if *file == "" {
			fail(fmt.Errorf("--file is required"))
		}
		f, err := os.Open(*file)
		if err != nil {
			fail(err)
		}
		raw, err := io.ReadAll(io.LimitReader(f, sdk.MaxExport+1))
		_ = f.Close()
		if err != nil {
			fail(err)
		}
		var result any
		if command == "validate" {
			rows, e := sdk.ValidateJSONL(raw)
			if e != nil {
				fail(e)
			}
			result = map[string]any{"format": "connector-client-validation/v1", "events": len(rows), "valid": true}
		} else {
			result, err = sdk.Plan(raw)
			if err != nil {
				fail(err)
			}
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(result); err != nil {
			fail(err)
		}
	case "submit", "resume", "status", "replay":
		client := sdk.HostClient{Python: *python, HostScript: *script, Root: *root, HostConfig: *config, Authority: *authority, Namespace: *namespace, Export: *export, Timeout: time.Duration(*timeoutMS) * time.Millisecond}
		var receipt []byte
		var err error
		switch command {
		case "submit":
			if *stdin {
				receipt, err = client.SubmitStdin()
			} else {
				receipt, err = client.Submit()
			}
		case "resume":
			if *stdin {
				receipt, err = client.SubmitStdin()
			} else {
				receipt, err = client.Resume()
			}
		case "status":
			receipt, err = client.Status()
		case "replay":
			receipt, err = client.Replay(*line)
		}
		if err != nil {
			fail(err)
		}
		if _, err = os.Stdout.Write(receipt); err != nil {
			fail(err)
		}
	default:
		fail(fmt.Errorf("command must be validate, plan, submit, resume, status, or replay"))
	}
}
func fail(err error) { fmt.Fprintln(os.Stderr, "connector-sdk:", err); os.Exit(2) }
