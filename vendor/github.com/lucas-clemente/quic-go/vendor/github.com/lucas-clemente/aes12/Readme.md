# aes12

This package modifies the AES-GCM implementation from Go's standard library to use 12 byte tag sizes. It is not intended for a general audience, and used in [quic-go](https://github.com/lucas-clemente/quic-go).

To make use of the in-place encryption / decryption feature, the `dst` parameter to `Seal` and `Open` should be 16 bytes longer than plaintext, not 12.

Command for testing:

```
go test . --bench=. && GOARCH=386 go test . --bench=.
```

The output (on my machine):

```
BenchmarkAESGCMSeal1K-8   	 3000000	       467 ns/op	2192.37 MB/s
BenchmarkAESGCMOpen1K-8   	 3000000	       416 ns/op	2456.72 MB/s
BenchmarkAESGCMSeal8K-8   	  500000	      2742 ns/op	2986.53 MB/s
BenchmarkAESGCMOpen8K-8   	  500000	      2791 ns/op	2934.65 MB/s
PASS
ok  	github.com/lucas-clemente/aes12	6.383s
BenchmarkAESGCMSeal1K-8   	   50000	     35233 ns/op	  29.06 MB/s
BenchmarkAESGCMOpen1K-8   	   50000	     34529 ns/op	  29.66 MB/s
BenchmarkAESGCMSeal8K-8   	    5000	    262678 ns/op	  31.19 MB/s
BenchmarkAESGCMOpen8K-8   	    5000	    267296 ns/op	  30.65 MB/s
PASS
ok  	github.com/lucas-clemente/aes12	6.972s
```
