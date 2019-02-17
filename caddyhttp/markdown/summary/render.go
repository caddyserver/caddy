// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package summary

import (
	"bytes"

	"github.com/russross/blackfriday"
)

// Ensure we implement the Blackfriday Markdown Renderer interface
var _ blackfriday.Renderer = (*renderer)(nil)

// renderer renders Markdown to plain-text meant for listings and excerpts,
// and implements the blackfriday.Renderer interface.
//
// Many of the methods are stubs with no output to prevent output of HTML markup.
type renderer struct{}

// Blocklevel callbacks

// BlockCode is the code tag callback.
func (r renderer) BlockCode(out *bytes.Buffer, text []byte, land string) {}

// BlockQuote is the quote tag callback.
func (r renderer) BlockQuote(out *bytes.Buffer, text []byte) {}

// BlockHtml is the HTML tag callback.
func (r renderer) BlockHtml(out *bytes.Buffer, text []byte) {}

// Header is the header tag callback.
func (r renderer) Header(out *bytes.Buffer, text func() bool, level int, id string) {}

// HRule is the horizontal rule tag callback.
func (r renderer) HRule(out *bytes.Buffer) {}

// List is the list tag callback.
func (r renderer) List(out *bytes.Buffer, text func() bool, flags int) {
	// TODO: This is not desired (we'd rather not write lists as part of summary),
	// but see this issue: https://github.com/russross/blackfriday/issues/189
	marker := out.Len()
	if !text() {
		out.Truncate(marker)
	}
	out.Write([]byte{' '})
}

// ListItem is the list item tag callback.
func (r renderer) ListItem(out *bytes.Buffer, text []byte, flags int) {}

// Paragraph is the paragraph tag callback.  This renders simple paragraph text
// into plain text, such that summaries can be easily generated.
func (r renderer) Paragraph(out *bytes.Buffer, text func() bool) {
	marker := out.Len()
	if !text() {
		out.Truncate(marker)
	}
	out.Write([]byte{' '})
}

// Table is the table tag callback.
func (r renderer) Table(out *bytes.Buffer, header []byte, body []byte, columnData []int) {}

// TableRow is the table row tag callback.
func (r renderer) TableRow(out *bytes.Buffer, text []byte) {}

// TableHeaderCell is the table header cell tag callback.
func (r renderer) TableHeaderCell(out *bytes.Buffer, text []byte, flags int) {}

// TableCell is the table cell tag callback.
func (r renderer) TableCell(out *bytes.Buffer, text []byte, flags int) {}

// Footnotes is the foot notes tag callback.
func (r renderer) Footnotes(out *bytes.Buffer, text func() bool) {}

// FootnoteItem is the footnote item tag callback.
func (r renderer) FootnoteItem(out *bytes.Buffer, name, text []byte, flags int) {}

// TitleBlock is the title tag callback.
func (r renderer) TitleBlock(out *bytes.Buffer, text []byte) {}

// Spanlevel callbacks

// AutoLink is the autolink tag callback.
func (r renderer) AutoLink(out *bytes.Buffer, link []byte, kind int) {}

// CodeSpan is the code span tag callback.  Outputs a simple Markdown version
// of the code span.
func (r renderer) CodeSpan(out *bytes.Buffer, text []byte) {
	out.Write([]byte("`"))
	out.Write(text)
	out.Write([]byte("`"))
}

// DoubleEmphasis is the double emphasis tag callback.  Outputs a simple
// plain-text version of the input.
func (r renderer) DoubleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Emphasis is the emphasis tag callback.  Outputs a simple plain-text
// version of the input.
func (r renderer) Emphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Image is the image tag callback.
func (r renderer) Image(out *bytes.Buffer, link []byte, title []byte, alt []byte) {}

// LineBreak is the line break tag callback.
func (r renderer) LineBreak(out *bytes.Buffer) {}

// Link is the link tag callback.  Outputs a simple plain-text version
// of the input.
func (r renderer) Link(out *bytes.Buffer, link []byte, title []byte, content []byte) {
	out.Write(content)
}

// RawHtmlTag is the raw HTML tag callback.
func (r renderer) RawHtmlTag(out *bytes.Buffer, tag []byte) {}

// TripleEmphasis is the triple emphasis tag callback.  Outputs a simple plain-text
// version of the input.
func (r renderer) TripleEmphasis(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// StrikeThrough is the strikethrough tag callback.
func (r renderer) StrikeThrough(out *bytes.Buffer, text []byte) {}

// FootnoteRef is the footnote ref tag callback.
func (r renderer) FootnoteRef(out *bytes.Buffer, ref []byte, id int) {}

// Lowlevel callbacks

// Entity callback.  Outputs a simple plain-text version of the input.
func (r renderer) Entity(out *bytes.Buffer, entity []byte) {
	out.Write(entity)
}

// NormalText callback.  Outputs a simple plain-text version of the input.
func (r renderer) NormalText(out *bytes.Buffer, text []byte) {
	out.Write(text)
}

// Header and footer

// DocumentHeader callback.
func (r renderer) DocumentHeader(out *bytes.Buffer) {}

// DocumentFooter callback.
func (r renderer) DocumentFooter(out *bytes.Buffer) {}

// GetFlags returns zero.
func (r renderer) GetFlags() int { return 0 }
