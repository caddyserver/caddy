package summary

import (
	"bytes"

	"github.com/russross/blackfriday"
)

// Markdown formats input using a plain-text renderer, and
// then returns up to the first `wordcount` words as a summary.
func Markdown(input []byte, wordcount int) []byte {
	words := bytes.Fields(blackfriday.Markdown(input, renderer{}, 0))
	if wordcount > len(words) {
		wordcount = len(words)
	}
	return bytes.Join(words[0:wordcount], []byte{' '})
}
