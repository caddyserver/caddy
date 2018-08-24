package qerr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"runtime"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("error codes", func() {
	// If this test breaks, you should run `go generate ./...`
	It("has a string representation for every error code", func() {
		// We parse the error code file, extract all constants, and verify that
		// each of them has a string version. Go FTW!
		_, thisfile, _, ok := runtime.Caller(0)
		if !ok {
			panic("Failed to get current frame")
		}
		filename := path.Join(path.Dir(thisfile), "error_codes.go")
		fileAst, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		Expect(err).NotTo(HaveOccurred())
		constSpecs := fileAst.Decls[0].(*ast.GenDecl).Specs
		Expect(len(constSpecs)).To(BeNumerically(">", 4)) // at time of writing
		for _, c := range constSpecs {
			name := c.(*ast.ValueSpec).Names[0].Name
			valString := c.(*ast.ValueSpec).Values[0].(*ast.BasicLit).Value
			val, err := strconv.Atoi(valString)
			Expect(err).NotTo(HaveOccurred())
			Expect(ErrorCode(val).String()).To(Equal(name))
		}
		Expect(ErrorCode(0).String()).To(Equal("ErrorCode(0)"))
	})
})
