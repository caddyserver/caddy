package summary

import (
	"bytes"

	"github.com/russross/blackfriday"
)

func Markdown(input []byte, wordcount int) []byte {
	words := bytes.Fields(blackfriday.Markdown(input, Renderer{}, 0))
	if wordcount > len(words) {
		wordcount = len(words)
	}

	return bytes.Join(words[0:wordcount], []byte{' '})
}
