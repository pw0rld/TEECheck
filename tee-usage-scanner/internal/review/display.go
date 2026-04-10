package review

import (
	"fmt"
	"io"
	"strings"

	"github.com/pw0rld/TEECheck/tee-usage-scanner/internal/artifacts"
)

func DisplayPacketSummary(w io.Writer, idx, total int, finding artifacts.FindingItem, packetText string) {
	bar := strings.Repeat("━", 50)
	fmt.Fprintf(w, "\n%s\n", bar)
	fmt.Fprintf(w, "Case %d/%d: %s\n", idx+1, total, finding.FindingID)
	fmt.Fprintf(w, "Status: %s | Confidence: %s | Severity: %s\n", finding.Status, finding.Confidence, finding.Severity)
	fmt.Fprintf(w, "%s\n\n", bar)
	fmt.Fprintln(w, packetText)
	fmt.Fprintf(w, "%s\n", bar)
}
