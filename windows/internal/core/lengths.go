package core

// Limits and wording for 5-minute approvals and grants, the same as touchenv.swift's.

import (
	"fmt"
	"strings"
	"time"
)

const (
	ApprovalLength = 5 * time.Minute
	MaxGrantLength = 24 * time.Hour
	MinGrantLength = time.Minute
	MaxGrantUses   = 500
)

// ParseLength reads "8h", "30m" or "1h30m" (each unit once, at most five digits each), as touchenv.swift's
// parseLength does. false for anything else, and for zero.
func ParseLength(text string) (time.Duration, bool) {
	total, digits, seen := 0, "", ""
	for _, ch := range text {
		switch {
		case ch >= '0' && ch <= '9' && len(digits) < 5:
			digits += string(ch)
		case (ch == 'h' || ch == 'm') && !strings.ContainsRune(seen, ch) && digits != "":
			n := 0
			for _, d := range digits {
				n = n*10 + int(d-'0')
			}
			if ch == 'h' {
				total += n * 3600
			} else {
				total += n * 60
			}
			digits = ""
			seen += string(ch)
		default:
			return 0, false
		}
	}
	if digits != "" || total <= 0 {
		return 0, false
	}
	return time.Duration(total) * time.Second, true
}

// SpokenLength: "8 hours", "1 hour 30 minutes".
func SpokenLength(d time.Duration) string {
	minutes := int(d / time.Minute)
	var parts []string
	if minutes >= 60 {
		parts = append(parts, fmt.Sprintf("%d hour%s", minutes/60, plural(minutes/60)))
	}
	if minutes%60 > 0 {
		parts = append(parts, fmt.Sprintf("%d minute%s", minutes%60, plural(minutes%60)))
	}
	return strings.Join(parts, " ")
}

// Clock: time left as 4:59 or 7:59:59.
func Clock(seconds int) string {
	if seconds >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", seconds/3600, seconds/60%60, seconds%60)
	}
	return fmt.Sprintf("%d:%02d", seconds/60, seconds%60)
}

// Times: "1 time", "20 times".
func Times(n int) string {
	if n == 1 {
		return "1 time"
	}
	return fmt.Sprintf("%d times", n)
}

// secondsLeft rounds up, as the Swift agent does.
func secondsLeft(until, now time.Time) int {
	d := until.Sub(now)
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}
