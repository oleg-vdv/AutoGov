package report

// Minimal PDF 1.4 writer: enough for a paginated monospace text report with
// zero external dependencies (offline / air-gapped requirement, ТЗ §8.4).

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

const (
	pdfLinesPerPage = 54
	pdfFontSize     = 9
	pdfLeading      = 13
	pdfMarginX      = 40
	pdfTopY         = 800
)

// writePDFLines renders text lines into a multi-page PDF document.
func writePDFLines(w io.Writer, lines []string) error {
	var pages [][]string
	for start := 0; start < len(lines); start += pdfLinesPerPage {
		end := start + pdfLinesPerPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, lines[start:end])
	}
	if len(pages) == 0 {
		pages = [][]string{{"(empty report)"}}
	}

	// Object layout: 1=catalog, 2=pages, 3=font, then per page: page obj + content obj.
	type object struct{ body []byte }
	var objects []object
	addObj := func(body string) int {
		objects = append(objects, object{[]byte(body)})
		return len(objects) // 1-based object number
	}

	catalogNum := addObj("") // placeholder, filled after pages known
	pagesNum := addObj("")
	fontNum := addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")

	var pageNums []int
	for _, pageLines := range pages {
		var content bytes.Buffer
		fmt.Fprintf(&content, "BT /F1 %d Tf %d %d Td %d TL\n", pdfFontSize, pdfMarginX, pdfTopY, pdfLeading)
		for i, line := range pageLines {
			if i > 0 {
				content.WriteString("T*\n")
			}
			fmt.Fprintf(&content, "(%s) Tj\n", pdfEscape(line))
		}
		content.WriteString("ET")
		contentNum := addObj(fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", content.Len(), content.String()))
		pageNum := addObj(fmt.Sprintf(
			"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 595 842] /Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>",
			pagesNum, contentNum, fontNum))
		pageNums = append(pageNums, pageNum)
	}

	kids := make([]string, len(pageNums))
	for i, n := range pageNums {
		kids[i] = fmt.Sprintf("%d 0 R", n)
	}
	objects[catalogNum-1].body = []byte(fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesNum))
	objects[pagesNum-1].body = []byte(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pageNums)))

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, o := range objects {
		offsets[i+1] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, o.body)
	}
	xrefPos := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, catalogNum, xrefPos)
	_, err := w.Write(buf.Bytes())
	return err
}

// pdfEscape escapes PDF string syntax and maps non-Latin-1 runes to '?'
// (the machine-readable report is JSON; PDF is a human summary).
func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '(', ')', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			if r < 32 {
				b.WriteByte(' ')
			} else if r < 256 {
				b.WriteRune(r)
			} else {
				b.WriteString(translit(r))
			}
		}
	}
	return b.String()
}

// translit maps common Cyrillic to Latin so PDF summaries stay readable.
func translit(r rune) string {
	m := map[rune]string{
		'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e", 'ж': "zh",
		'з': "z", 'и': "i", 'й': "y", 'к': "k", 'л': "l", 'м': "m", 'н': "n", 'о': "o",
		'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u", 'ф': "f", 'х': "h", 'ц': "ts",
		'ч': "ch", 'ш': "sh", 'щ': "sch", 'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "yu",
		'я': "ya",
		'А': "A", 'Б': "B", 'В': "V", 'Г': "G", 'Д': "D", 'Е': "E", 'Ё': "E", 'Ж': "Zh",
		'З': "Z", 'И': "I", 'Й': "Y", 'К': "K", 'Л': "L", 'М': "M", 'Н': "N", 'О': "O",
		'П': "P", 'Р': "R", 'С': "S", 'Т': "T", 'У': "U", 'Ф': "F", 'Х': "H", 'Ц': "Ts",
		'Ч': "Ch", 'Ш': "Sh", 'Щ': "Sch", 'Ъ': "", 'Ы': "Y", 'Ь': "", 'Э': "E", 'Ю': "Yu",
		'Я': "Ya",
	}
	if v, ok := m[r]; ok {
		return v
	}
	return "?"
}
