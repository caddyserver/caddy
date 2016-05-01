package summary

import (
	"bytes"

	"github.com/russross/blackfriday"
)

// Ensure we implement the Blackfriday Markdown Renderer interface
var _ blackfriday.Renderer = (*Renderer)(nil)

// Renderer is a plain-text Markdown renderer that implements the
// blackfriday.Renderer interface.  Many of the required methods are
// stubs with no output.
type Renderer struct{}

// Blocklevel callbacks

// Stub BlockCode is the code tag callback.
func (r Renderer) BlockCode(out *bytes.Buffer, text []byte, land string) {}

// Stub BlockQuote is teh quote tag callback.
func (r Renderer) BlockQuote(out *bytes.Buffer, text []byte) {}

// Stub BlockHtml is the HTML tag callback.
func (r Renderer) BlockHtml(out *bytes.Buffer, text []byte) {}

// Stub Header is the header tag callback.
func (r Renderer) Header(out *bytes.Buffer, text func() bool, level int, id string) {}

// Stub HRule is the horizontal rule tag callback.
func (r Renderer) HRule(out *bytes.Buffer) {}

// List is the list tag callback.
func (r Renderer) List(out *bytes.Buffer, text func() bool, flags int) {
	// TODO: This is not desired (we'd rather not write lists as part of summary),
	// but see this issue: https://github.com/russross/blackfriday/issues/189
	marker := out.Len()
	if !text() {
		out.Truncate(marker)
	}
	out.Write([]byte{' '})
}

// Stub ListItem is the list item tag callback.
func (r Renderer) ListItem(out *bytes.Buffer, text []byte, flags int) {}

// Paragraph is the paragraph tag callback.  This renders simple paragraph text
// into plain text, such that summaries can be easily generated.
func (r Renderer) Paragraph(out *bytes.Buffer, text func() bool) {
	marker := out.Len()
	if !text() {
		out.Truncate(marker)
	}
	out.Write([]byte{' '})
}

// Stub Table is the table tag callback.
func (r Renderer) Table(out *bytes.Buffer, header []byte, body []byte, columnData []int) {}

// Stub TableRow is the table row tag callback.
func (r Renderer) TableRow(out *bytes.Buffer, text []byte) {}

// Stub TableHeaderCell is the table header cell tag callback.
func (r Renderer) TableHeaderCell(out *bytes.Buffer, text []byte, flags int) {}

// Stub TableCell is the table cell tag callback.
func (r Renderer) TableCell(out *bytes.Buffer, text []byte, flags int) {}

// Stub Footnotes is the foot notes tag callback.
func (r Renderer) Footnotes(out *bytes.Buffer, text func() bool) {}

// Stub FootnoteItem is the footnote item tag callback.
func (r Renderer) FootnoteItem(out *bytes.Buffer, name, text []byte, flags int) {}

// Stub TitleBlock is the title tag callback.
func (r Renderer) TitleBlock(out *bytes.Buffer, text []byte) {}

// Spanlevel callbacks

// Stub AutoLink is the autolink tag callback.
func (r Renderer) AutoLink(out *bytes.Buffer, link []byte, kind int) {}

// CodeSpan is the code span tag callback.  Outputs a simple Markdown version
// of the code span.
func (r Renderer) CodeSpan(out *bytes.Buffer, text []byte) {
	out.Write([]byte("`"))
	out.Write(text)
	out.Write([]byte("`"))
}

// DoubleEmphasis is the double emphasis tag callback.  Outputs a simple
// plain-text version of the input.
func (r Renderer) DoubleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Emphasis is the emphasis tag callback.  Outputs a simple plain-text
// version of the input.
func (r Renderer) Emphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Stub Image is the image tag callback.
func (r Renderer) Image(out *bytes.Buffer, link []byte, title []byte, alt []byte) {}

// Stub LineBreak is the line break tag callback.
func (r Renderer) LineBreak(out *bytes.Buffer) {}

// Link is the link tag callback.  Outputs a sipmle plain-text version
// of the input.
func (r Renderer) Link(out *bytes.Buffer, link []byte, title []byte, content []byte) {
	out.Write(content)
}

// Stub RawHtmlTag is the raw HTML tag callback.
func (r Renderer) RawHtmlTag(out *bytes.Buffer, tag []byte) {}

// TripleEmphasis is the triple emphasis tag callback.  Outputs a simple plain-text
// version of the input.
func (r Renderer) TripleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Stub StrikeThrough is the strikethrough tag callback.
func (r Renderer) StrikeThrough(out *bytes.Buffer, text []byte) {}

// Stub FootnoteRef is the footnote ref tag callback.
func (r Renderer) FootnoteRef(out *bytes.Buffer, ref []byte, id int) {}

// Lowlevel callbacks

// Entity callback.  Outputs a simple plain-text version of the input.
func (r Renderer) Entity(out *bytes.Buffer, entity []byte) {
	out.Write(entity)
}

// NormalText callback.  Outputs a simple plain-text version of the input.
func (r Renderer) NormalText(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Header and footer

// Stub DocumentHeader callback.
func (r Renderer) DocumentHeader(out *bytes.Buffer) {}

// Stub DocumentFooter callback.
func (r Renderer) DocumentFooter(out *bytes.Buffer) {}

// Stub GetFlags returns zero.
func (r Renderer) GetFlags() int { return 0 }
