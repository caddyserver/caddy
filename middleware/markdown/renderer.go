package markdown

import (
	"bytes"
)

type PlaintextRenderer struct{}

// Block-level callbacks

func (r PlaintextRenderer) BlockCode(out *bytes.Buffer, text []byte, lang string) {}

func (r PlaintextRenderer) BlockQuote(out *bytes.Buffer, text []byte) {}

func (r PlaintextRenderer) BlockHtml(out *bytes.Buffer, text []byte) {}

func (r PlaintextRenderer) Header(out *bytes.Buffer, text func() bool, level int, id string) {}

func (r PlaintextRenderer) HRule(out *bytes.Buffer) {}

func (r PlaintextRenderer) List(out *bytes.Buffer, text func() bool, flags int) {}

func (r PlaintextRenderer) ListItem(out *bytes.Buffer, text []byte, flags int) {}

func (r PlaintextRenderer) Paragraph(out *bytes.Buffer, text func() bool) {
	marker := out.Len()
	if !text() {
		out.Truncate(marker)
	}
	out.Write([]byte{' '})
}

func (r PlaintextRenderer) Table(out *bytes.Buffer, header []byte, body []byte, columnData []int) {}

func (r PlaintextRenderer) TableRow(out *bytes.Buffer, text []byte) {}

func (r PlaintextRenderer) TableHeaderCell(out *bytes.Buffer, text []byte, flags int) {}

func (r PlaintextRenderer) TableCell(out *bytes.Buffer, text []byte, flags int) {}

func (r PlaintextRenderer) Footnotes(out *bytes.Buffer, text func() bool) {}

func (r PlaintextRenderer) FootnoteItem(out *bytes.Buffer, name, text []byte, flags int) {}

func (r PlaintextRenderer) TitleBlock(out *bytes.Buffer, text []byte) {}

// Span-level callbacks

func (r PlaintextRenderer) AutoLink(out *bytes.Buffer, link []byte, kind int) {}

func (r PlaintextRenderer) CodeSpan(out *bytes.Buffer, text []byte) {}

func (r PlaintextRenderer) DoubleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

func (r PlaintextRenderer) Emphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

func (r PlaintextRenderer) Image(out *bytes.Buffer, link []byte, title []byte, alt []byte) {}

func (r PlaintextRenderer) LineBreak(out *bytes.Buffer) {}

func (r PlaintextRenderer) Link(out *bytes.Buffer, link []byte, title []byte, content []byte) {
	out.Write(content)
}
func (r PlaintextRenderer) RawHtmlTag(out *bytes.Buffer, tag []byte) {}

func (r PlaintextRenderer) TripleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}
func (r PlaintextRenderer) StrikeThrough(out *bytes.Buffer, text []byte) {}

func (r PlaintextRenderer) FootnoteRef(out *bytes.Buffer, ref []byte, id int) {}

// Low-level callbacks

func (r PlaintextRenderer) Entity(out *bytes.Buffer, entity []byte) {
	out.Write(entity)
}

func (r PlaintextRenderer) NormalText(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Header and footer

func (r PlaintextRenderer) DocumentHeader(out *bytes.Buffer) {}

func (r PlaintextRenderer) DocumentFooter(out *bytes.Buffer) {}

func (r PlaintextRenderer) GetFlags() int { return 0 }
