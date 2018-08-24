package utils

import (
	"bytes"
	"log"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Log", func() {
	var b *bytes.Buffer

	BeforeEach(func() {
		b = &bytes.Buffer{}
		log.SetOutput(b)
	})

	AfterEach(func() {
		log.SetOutput(os.Stdout)
		DefaultLogger.SetLogLevel(LogLevelNothing)
	})

	It("the log level has the correct numeric value", func() {
		Expect(LogLevelNothing).To(BeEquivalentTo(0))
		Expect(LogLevelError).To(BeEquivalentTo(1))
		Expect(LogLevelInfo).To(BeEquivalentTo(2))
		Expect(LogLevelDebug).To(BeEquivalentTo(3))
	})

	It("log level nothing", func() {
		DefaultLogger.SetLogLevel(LogLevelNothing)
		DefaultLogger.Debugf("debug")
		DefaultLogger.Infof("info")
		DefaultLogger.Errorf("err")
		Expect(b.String()).To(BeEmpty())
	})

	It("log level err", func() {
		DefaultLogger.SetLogLevel(LogLevelError)
		DefaultLogger.Debugf("debug")
		DefaultLogger.Infof("info")
		DefaultLogger.Errorf("err")
		Expect(b.String()).To(ContainSubstring("err\n"))
		Expect(b.String()).ToNot(ContainSubstring("info"))
		Expect(b.String()).ToNot(ContainSubstring("debug"))
	})

	It("log level info", func() {
		DefaultLogger.SetLogLevel(LogLevelInfo)
		DefaultLogger.Debugf("debug")
		DefaultLogger.Infof("info")
		DefaultLogger.Errorf("err")
		Expect(b.String()).To(ContainSubstring("err\n"))
		Expect(b.String()).To(ContainSubstring("info\n"))
		Expect(b.String()).ToNot(ContainSubstring("debug"))
	})

	It("log level debug", func() {
		DefaultLogger.SetLogLevel(LogLevelDebug)
		DefaultLogger.Debugf("debug")
		DefaultLogger.Infof("info")
		DefaultLogger.Errorf("err")
		Expect(b.String()).To(ContainSubstring("err\n"))
		Expect(b.String()).To(ContainSubstring("info\n"))
		Expect(b.String()).To(ContainSubstring("debug\n"))
	})

	It("doesn't add a timestamp if the time format is empty", func() {
		DefaultLogger.SetLogLevel(LogLevelDebug)
		DefaultLogger.SetLogTimeFormat("")
		DefaultLogger.Debugf("debug")
		Expect(b.String()).To(Equal("debug\n"))
	})

	It("adds a timestamp", func() {
		format := "Jan 2, 2006"
		DefaultLogger.SetLogTimeFormat(format)
		DefaultLogger.SetLogLevel(LogLevelInfo)
		DefaultLogger.Infof("info")
		t, err := time.Parse(format, string(b.String()[:b.Len()-6]))
		Expect(err).ToNot(HaveOccurred())
		Expect(t).To(BeTemporally("~", time.Now(), 25*time.Hour))
	})

	It("says whether debug is enabled", func() {
		Expect(DefaultLogger.Debug()).To(BeFalse())
		DefaultLogger.SetLogLevel(LogLevelDebug)
		Expect(DefaultLogger.Debug()).To(BeTrue())
	})

	It("adds a prefix", func() {
		DefaultLogger.SetLogLevel(LogLevelDebug)
		prefixLogger := DefaultLogger.WithPrefix("prefix")
		prefixLogger.Debugf("debug")
		Expect(b.String()).To(ContainSubstring("prefix"))
		Expect(b.String()).To(ContainSubstring("debug"))
	})

	It("adds multiple prefixes", func() {
		DefaultLogger.SetLogLevel(LogLevelDebug)
		prefixLogger := DefaultLogger.WithPrefix("prefix1")
		prefixPrefixLogger := prefixLogger.WithPrefix("prefix2")
		prefixPrefixLogger.Debugf("debug")
		Expect(b.String()).To(ContainSubstring("prefix"))
		Expect(b.String()).To(ContainSubstring("debug"))
	})

	Context("reading from env", func() {
		BeforeEach(func() {
			Expect(DefaultLogger.(*defaultLogger).logLevel).To(Equal(LogLevelNothing))
		})

		It("reads DEBUG", func() {
			os.Setenv(logEnv, "DEBUG")
			Expect(readLoggingEnv()).To(Equal(LogLevelDebug))
		})

		It("reads debug", func() {
			os.Setenv(logEnv, "debug")
			Expect(readLoggingEnv()).To(Equal(LogLevelDebug))
		})

		It("reads INFO", func() {
			os.Setenv(logEnv, "INFO")
			readLoggingEnv()
			Expect(readLoggingEnv()).To(Equal(LogLevelInfo))
		})

		It("reads ERROR", func() {
			os.Setenv(logEnv, "ERROR")
			Expect(readLoggingEnv()).To(Equal(LogLevelError))
		})

		It("does not error reading invalid log levels from env", func() {
			os.Setenv(logEnv, "")
			Expect(readLoggingEnv()).To(Equal(LogLevelNothing))
			os.Setenv(logEnv, "asdf")
			Expect(readLoggingEnv()).To(Equal(LogLevelNothing))
		})
	})
})
