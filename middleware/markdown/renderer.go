package markdown

import (
	"bytes"
)

type SummaryRenderer struct{}

// Block-level callbacks

func (r SummaryRenderer) BlockCode(out *bytes.Buffer, text []byte, lang string) {}

func (r SummaryRenderer) BlockQuote(out *bytes.Buffer, text []byte) {}

func (r SummaryRenderer) BlockHtml(out *bytes.Buffer, text []byte) {}

func (r SummaryRenderer) Header(out *bytes.Buffer, text func() bool, level int, id string) {}

func (r SummaryRenderer) HRule(out *bytes.Buffer) {}

func (r SummaryRenderer) List(out *bytes.Buffer, text func() bool, flags int) {
	// TODO: This is not desired (we'd rather not write lists as part of summary),
	// but see this issue: https://github.com/russross/blackfriday/issues/189
	marker := out.Len()
	if !text() {
		out.Truncate(marker)
	}
	out.Write([]byte{' '})
}

func (r SummaryRenderer) ListItem(out *bytes.Buffer, text []byte, flags int) {}

func (r SummaryRenderer) Paragraph(out *bytes.Buffer, text func() bool) {
	marker := out.Len()
	if !text() {
		out.Truncate(marker)
	}
	out.Write([]byte{' '})
}

func (r SummaryRenderer) Table(out *bytes.Buffer, header []byte, body []byte, columnData []int) {}

func (r SummaryRenderer) TableRow(out *bytes.Buffer, text []byte) {}

func (r SummaryRenderer) TableHeaderCell(out *bytes.Buffer, text []byte, flags int) {}

func (r SummaryRenderer) TableCell(out *bytes.Buffer, text []byte, flags int) {}

func (r SummaryRenderer) Footnotes(out *bytes.Buffer, text func() bool) {}

func (r SummaryRenderer) FootnoteItem(out *bytes.Buffer, name, text []byte, flags int) {}

func (r SummaryRenderer) TitleBlock(out *bytes.Buffer, text []byte) {}

// Span-level callbacks

func (r SummaryRenderer) AutoLink(out *bytes.Buffer, link []byte, kind int) {}

func (r SummaryRenderer) CodeSpan(out *bytes.Buffer, text []byte) {
	out.Write([]byte("`"))
	out.Write(text)
	out.Write([]byte("`"))
}

func (r SummaryRenderer) DoubleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

func (r SummaryRenderer) Emphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

func (r SummaryRenderer) Image(out *bytes.Buffer, link []byte, title []byte, alt []byte) {}

func (r SummaryRenderer) LineBreak(out *bytes.Buffer) {}

func (r SummaryRenderer) Link(out *bytes.Buffer, link []byte, title []byte, content []byte) {
	out.Write(content)
}
func (r SummaryRenderer) RawHtmlTag(out *bytes.Buffer, tag []byte) {}

func (r SummaryRenderer) TripleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}
func (r SummaryRenderer) StrikeThrough(out *bytes.Buffer, text []byte) {}

func (r SummaryRenderer) FootnoteRef(out *bytes.Buffer, ref []byte, id int) {}

// Low-level callbacks

func (r SummaryRenderer) Entity(out *bytes.Buffer, entity []byte) {
	out.Write(entity)
}

func (r SummaryRenderer) NormalText(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Header and footer

func (r SummaryRenderer) DocumentHeader(out *bytes.Buffer) {}

func (r SummaryRenderer) DocumentFooter(out *bytes.Buffer) {}

func (r SummaryRenderer) GetFlags() int { return 0 }
