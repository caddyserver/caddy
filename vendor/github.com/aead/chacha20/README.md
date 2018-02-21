[![Godoc Reference](https://godoc.org/github.com/aead/chacha20?status.svg)](https://godoc.org/github.com/aead/chacha20)

## The ChaCha20 stream cipher

ChaCha is a stream cipher family created by Daniel J. Bernstein.  
The most common ChaCha cipher is ChaCha20 (20 rounds). ChaCha20 is standardized in [RFC 7539](https://tools.ietf.org/html/rfc7539 "RFC 7539").

This package provides implementations of three ChaCha versions:
- ChaCha20 with a 64 bit nonce (can en/decrypt up to 2^64 * 64 bytes for one key-nonce combination)  
- ChaCha20 with a 96 bit nonce (can en/decrypt up to 2^32 * 64 bytes ~ 256 GB for one key-nonce combination)  
- XChaCha20 with a 192 bit nonce (can en/decrypt up to 2^64 * 64 bytes for one key-nonce combination)  

Furthermore the chacha subpackage implements ChaCha20/12 and ChaCha20/8.
These versions use 12 or 8 rounds instead of 20.
But it's recommended to use ChaCha20 (with 20 rounds) - it will be fast enough for almost all purposes. 

### Installation 
Install in your GOPATH: `go get -u github.com/aead/chacha20`

### Requirements
All go versions >= 1.5.3 are supported.  
Please notice, that the amd64 AVX2 asm implementation requires go1.7 or newer.

### Performance

#### AMD64
Hardware: Intel i7-6500U 2.50GHz x 2  
System: Linux Ubuntu 16.04 - kernel: 4.4.0-62-generic  
Go version: 1.8.0  
```
AVX2
name                        speed              cpb
ChaCha20_64-4                573MB/s ± 0%      4.16
ChaCha20_1K-4               2.19GB/s ± 0%      1.06
XChaCha20_64-4               261MB/s ± 0%      9.13
XChaCha20_1K-4              1.69GB/s ± 4%      1.37
XORKeyStream64-4             474MB/s ± 2%      5.02
XORKeyStream1K-4            2.09GB/s ± 1%      1.11
XChaCha20_XORKeyStream64-4   262MB/s ± 0%      9.09
XChaCha20_XORKeyStream1K-4  1.71GB/s ± 1%      1.36

SSSE3
name                        speed              cpb
ChaCha20_64-4                583MB/s ± 0%      4.08
ChaCha20_1K-4               1.15GB/s ± 1%      2.02
XChaCha20_64-4               267MB/s ± 0%      8.92
XChaCha20_1K-4               984MB/s ± 5%      2.42
XORKeyStream64-4             492MB/s ± 1%      4.84
XORKeyStream1K-4            1.10GB/s ± 5%      2.11
XChaCha20_XORKeyStream64-4   266MB/s ± 0%      8.96
XChaCha20_XORKeyStream1K-4  1.00GB/s ± 2%      2.32
```
#### 386
Hardware: Intel i7-6500U 2.50GHz x 2  
System: Linux Ubuntu 16.04 - kernel: 4.4.0-62-generic  
Go version: 1.8.0  
```
SSSE3
name                        speed              cpb
ChaCha20_64-4               570MB/s ± 0%       4.18
ChaCha20_1K-4               650MB/s ± 0%       3.66
XChaCha20_64-4              223MB/s ± 0%      10.69
XChaCha20_1K-4              584MB/s ± 1%       4.08
XORKeyStream64-4            392MB/s ± 1%       6.08
XORKeyStream1K-4            629MB/s ± 1%       3.79
XChaCha20_XORKeyStream64-4  222MB/s ± 0%      10.73
XChaCha20_XORKeyStream1K-4  585MB/s ± 0%       4.07

SSE2
name                        speed              cpb
ChaCha20_64-4               509MB/s ± 0%       4.68
ChaCha20_1K-4               553MB/s ± 2%       4.31
XChaCha20_64-4              201MB/s ± 0%      11.86
XChaCha20_1K-4              498MB/s ± 4%       4.78
XORKeyStream64-4            359MB/s ± 1%       6.64
XORKeyStream1K-4            545MB/s ± 0%       4.37
XChaCha20_XORKeyStream64-4  201MB/s ± 1%      11.86
XChaCha20_XORKeyStream1K-4  507MB/s ± 0%       4.70
```
