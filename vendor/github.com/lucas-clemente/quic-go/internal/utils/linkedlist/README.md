# Usage

This is the Go standard library implementation of a linked list 
(https://golang.org/src/container/list/list.go), modified such that genny
(https://github.com/cheekybits/genny) can be used to generate a typed linked
list.

To generate, run
```
genny -pkg $PACKAGE -in linkedlist.go -out $OUTFILE gen Item=$TYPE
```
