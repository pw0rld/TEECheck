package review

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func PromptVerdict(r *bufio.Scanner, w io.Writer) string {
	fmt.Fprint(w, "Verdict? [c]onfirm / [d]ismiss / [i]nconclusive / [s]kip / [q]uit: ")
	if !r.Scan() {
		return "quit"
	}
	switch strings.ToLower(strings.TrimSpace(r.Text())) {
	case "c", "confirm":
		return "confirmed"
	case "d", "dismiss":
		return "dismissed"
	case "i", "inconclusive":
		return "inconclusive"
	case "s", "skip":
		return "skip"
	default:
		return "quit"
	}
}

func PromptSeverityOverride(r *bufio.Scanner, w io.Writer, current string) string {
	fmt.Fprintf(w, "Severity override (high/medium/low) [enter=keep %s]: ", current)
	if !r.Scan() {
		return current
	}
	text := strings.ToLower(strings.TrimSpace(r.Text()))
	switch text {
	case "high", "medium", "low":
		return text
	default:
		return current
	}
}

func PromptTags(r *bufio.Scanner, w io.Writer) []string {
	fmt.Fprint(w, "Tags (comma-separated): ")
	if !r.Scan() {
		return nil
	}
	raw := strings.TrimSpace(r.Text())
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var tags []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			tags = append(tags, p)
		}
	}
	return tags
}

func PromptNotes(r *bufio.Scanner, w io.Writer) string {
	fmt.Fprint(w, "Notes: ")
	if !r.Scan() {
		return ""
	}
	return strings.TrimSpace(r.Text())
}
