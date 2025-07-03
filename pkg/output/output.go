package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/lokeshllkumar/sec-aws/internal/logger"
	"github.com/lokeshllkumar/sec-aws/internal/scanner"
)

// defines the supported output formats
type OutputFormat string

const FormatTable OutputFormat = "table"
const FormatJSON OutputFormat = "json"
const FormatCSV OutputFormat = "csv"

// displays the vulnerability findings in the specified format
func PrintFindings(findings []scanner.Vulnerability, format OutputFormat) error {
	if len(findings) == 0 {
		logger.Log.Warn("No vulnerabilities found")
		return nil
	}

	// sorting findings by severity
	sort.Slice(findings, func(i int, j int) bool {
		severityOrder := map[scanner.Severity]int{
			scanner.SeverityCritical: 1,
			scanner.SeverityHigh:     2,
			scanner.SeverityMedium:   3,
			scanner.SeverityLow:      4,
			scanner.SeverityInfo:     5,
		}
		if severityOrder[findings[i].Severity] != severityOrder[findings[j].Severity] {
			return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
		}
		return findings[i].ResourceID < findings[j].ResourceID
	})

	switch format {
	case FormatTable:
		return printTable(findings)
	case FormatJSON:
		return printJSON(findings)
	case FormatCSV:
		return printCSV(findings)
	default:
		return fmt.Errorf("unsopported output format: %s", format)
	}
}

func printTable(findings []scanner.Vulnerability) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tSeverity\tService\tResource ID\tDescription\tRegion\tAI Remediation")
	fmt.Fprintln(w, "--\t--------\t-------\t-----------\t-----------\t------\t--------------")

	for _, f := range findings {
		desc := f.Description
		// truncating for better readability
		if len(desc) > 50 {
			desc = desc[:47] + "..."
		}

		aiRemediation := f.AIRemediation
		// truncating again for better readability
		if len(aiRemediation) > 80 {
			aiRemediation = aiRemediation[:77] + "..."
		}
		aiRemediation = strings.ReplaceAll(aiRemediation, "\n", " ")

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.ID, f.Severity, f.Service, f.ResourceID, desc, f.Region, aiRemediation)
	}

	return w.Flush()
}

func printJSON(findings []scanner.Vulnerability) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}

func printCSV(findings []scanner.Vulnerability) error {
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	// defining the header
	header := []string{"ID", "Name", "Description", "Service", "Resource ID", "Resource ARN", "Region", "Severity", "Details", "Remediation ID", "AI Remediation", "Timestamp"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, f := range findings {
		detailBytes, _ := json.Marshal(f.Details)
		row := []string{
			f.ID,
			f.Name,
			f.Description,
			f.Service,
			f.ResourceID,
			f.ResourceARN,
			f.Region,
			string(f.Severity),
			string(detailBytes),
			f.RemediationID,
			f.AIRemediation,
			f.Timestamp,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}
