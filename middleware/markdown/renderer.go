package markdown

import (
	"bytes"
)

// SummaryRenderer represents a summary renderer.
type SummaryRenderer struct{}

// Block-level callbacks

// BlockCode is the code tag callback.
func (r SummaryRenderer) BlockCode(out *bytes.Buffer, text []byte, lang string) {}

// BlockQuote is the quote tag callback.
func (r SummaryRenderer) BlockQuote(out *bytes.Buffer, text []byte) {}

// BlockHtml is the HTML tag callback.
func (r SummaryRenderer) BlockHtml(out *bytes.Buffer, text []byte) {}

// Header is the header tag callback.
func (r SummaryRenderer) Header(out *bytes.Buffer, text func() bool, level int, id string) {}

// HRule is the horizontal rule tag callback.
func (r SummaryRenderer) HRule(out *bytes.Buffer) {}

// List is the list tag callback.
func (r SummaryRenderer) List(out *bytes.Buffer, text func() bool, flags int) {
	// TODO: This is not desired (we'd rather not write lists as part of summary),
	// but see this issue: https://github.com/russross/blackfriday/issues/189
	marker := out.Len()
	if !text() {
		out.Truncate(marker)
	}
	out.Write([]byte{' '})
}

// ListItem is the list item tag callback.
func (r SummaryRenderer) ListItem(out *bytes.Buffer, text []byte, flags int) {}

// Paragraph is the paragraph tag callback.
func (r SummaryRenderer) Paragraph(out *bytes.Buffer, text func() bool) {
	marker := out.Len()
	if !text() {
		out.Truncate(marker)
	}
	out.Write([]byte{' '})
}

// Table is the table tag callback.
func (r SummaryRenderer) Table(out *bytes.Buffer, header []byte, body []byte, columnData []int) {}

// TableRow is the table row tag callback.
func (r SummaryRenderer) TableRow(out *bytes.Buffer, text []byte) {}

// TableHeaderCell is the table header cell tag callback.
func (r SummaryRenderer) TableHeaderCell(out *bytes.Buffer, text []byte, flags int) {}

// TableCell is the table cell tag callback.
func (r SummaryRenderer) TableCell(out *bytes.Buffer, text []byte, flags int) {}

// Footnotes is the foot notes tag callback.
func (r SummaryRenderer) Footnotes(out *bytes.Buffer, text func() bool) {}

// FootnoteItem is the footnote item tag callback.
func (r SummaryRenderer) FootnoteItem(out *bytes.Buffer, name, text []byte, flags int) {}

// TitleBlock is the title tag callback.
func (r SummaryRenderer) TitleBlock(out *bytes.Buffer, text []byte) {}

// Span-level callbacks

// AutoLink is the autolink tag callback.
func (r SummaryRenderer) AutoLink(out *bytes.Buffer, link []byte, kind int) {}

// CodeSpan is the code span tag callback.
func (r SummaryRenderer) CodeSpan(out *bytes.Buffer, text []byte) {
	out.Write([]byte("`"))
	out.Write(text)
	out.Write([]byte("`"))
}

// DoubleEmphasis is the double emphasis tag callback.
func (r SummaryRenderer) DoubleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Emphasis is the emphasis tag callback.
func (r SummaryRenderer) Emphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Image is the image tag callback.
func (r SummaryRenderer) Image(out *bytes.Buffer, link []byte, title []byte, alt []byte) {}

// LineBreak is the line break tag callback.
func (r SummaryRenderer) LineBreak(out *bytes.Buffer) {}

// Link is the link tag callback.
func (r SummaryRenderer) Link(out *bytes.Buffer, link []byte, title []byte, content []byte) {
	out.Write(content)
}

// RawHtmlTag is the raw HTML tag callback.
func (r SummaryRenderer) RawHtmlTag(out *bytes.Buffer, tag []byte) {}

// TripleEmphasis is the triple emphasis tag callback.
func (r SummaryRenderer) TripleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// StrikeThrough is the strikethrough tag callback.
func (r SummaryRenderer) StrikeThrough(out *bytes.Buffer, text []byte) {}

// FootnoteRef is the footnote ref tag callback.
func (r SummaryRenderer) FootnoteRef(out *bytes.Buffer, ref []byte, id int) {}

// Low-level callbacks

// Entity callback.
func (r SummaryRenderer) Entity(out *bytes.Buffer, entity []byte) {
	out.Write(entity)
}

// NormalText callback.
func (r SummaryRenderer) NormalText(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Header and footer

// DocumentHeader callback.
func (r SummaryRenderer) DocumentHeader(out *bytes.Buffer) {}

// DocumentFooter callback.
func (r SummaryRenderer) DocumentFooter(out *bytes.Buffer) {}

// GetFlags returns zero.
func (r SummaryRenderer) GetFlags() int { return 0 }
