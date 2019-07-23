package encode

import (
	"testing"
)

func BenchmarkOpenResponseWriter(b *testing.B) {
	enc := new(Encode)
	for n := 0; n < b.N; n++ {
		enc.openResponseWriter("test", nil)
	}
}
