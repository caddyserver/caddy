package protocol

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream ID", func() {
	Context("bidirectional streams", func() {
		It("doesn't allow any", func() {
			Expect(MaxBidiStreamID(0, PerspectiveClient)).To(Equal(StreamID(0)))
			Expect(MaxBidiStreamID(0, PerspectiveServer)).To(Equal(StreamID(0)))
		})

		It("allows one", func() {
			Expect(MaxBidiStreamID(1, PerspectiveClient)).To(Equal(StreamID(1)))
			Expect(MaxBidiStreamID(1, PerspectiveServer)).To(Equal(StreamID(4)))
		})

		It("allows many", func() {
			Expect(MaxBidiStreamID(100, PerspectiveClient)).To(Equal(StreamID(397)))
			Expect(MaxBidiStreamID(100, PerspectiveServer)).To(Equal(StreamID(400)))
		})
	})

	Context("unidirectional streams", func() {
		It("doesn't allow any", func() {
			Expect(MaxUniStreamID(0, PerspectiveClient)).To(Equal(StreamID(0)))
			Expect(MaxUniStreamID(0, PerspectiveServer)).To(Equal(StreamID(0)))
		})

		It("allows one", func() {
			Expect(MaxUniStreamID(1, PerspectiveClient)).To(Equal(StreamID(3)))
			Expect(MaxUniStreamID(1, PerspectiveServer)).To(Equal(StreamID(2)))
		})

		It("allows many", func() {
			Expect(MaxUniStreamID(100, PerspectiveClient)).To(Equal(StreamID(399)))
			Expect(MaxUniStreamID(100, PerspectiveServer)).To(Equal(StreamID(398)))
		})
	})
})
