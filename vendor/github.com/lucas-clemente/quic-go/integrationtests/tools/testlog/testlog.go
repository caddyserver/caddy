package testlog

import (
	"flag"
	"log"
	"os"

	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	logFileName string // the log file set in the ginkgo flags
	logFile     *os.File
)

// read the logfile command line flag
// to set call ginkgo -- -logfile=log.txt
func init() {
	flag.StringVar(&logFileName, "logfile", "", "log file")
}

var _ = BeforeEach(func() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if len(logFileName) > 0 {
		var err error
		logFile, err = os.Create(logFileName)
		Expect(err).ToNot(HaveOccurred())
		log.SetOutput(logFile)
		utils.DefaultLogger.SetLogLevel(utils.LogLevelDebug)
	}
})

var _ = AfterEach(func() {
	if len(logFileName) > 0 {
		_ = logFile.Close()
	}
})

// Debug says if this test is being logged
func Debug() bool {
	return len(logFileName) > 0
}
