package digestauth

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
)

var _ = log.Print

// Use an htdigest file from apache's htdigest command as a source of user authentication
// As provided it will read the file once. You may invoke .Reload() if you wish to track changes,
// perhaps in response to fsnotify.
type HtdigestUserStore struct {
	simpleUserStore
	mutex    sync.Mutex
	filename string
}

// Reload the htdigest's file. If there is an error, the old data will be kept instead.
// This function is thread safe.
func (us *HtdigestUserStore) Reload(onbad BadLineHandler) error {
	f, err := os.Open(us.filename)
	if err != nil {
		return err
	}
	defer f.Close()

	c := csv.NewReader(f)
	c.Comma = ':'
	c.Comment = '#'
	c.TrimLeadingSpace = true
	c.FieldsPerRecord = -1 // don't check

	n := map[string]string{}
	for {
		r, err := c.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(r) != 3 {
			if onbad != nil {
				// sad error message, there is some wreckage of better errors in encoding/csv, but
				// I'm not sure it is in use anymore.
				onbad(fmt.Errorf("line is not three fields: %v", r))
			}
			// skip this line, it isn't three fields
			continue
		}

		n[r[0]+":"+r[1]] = strings.TrimSpace(r[2]) // might have trailing space
	}

	us.mutex.Lock()
	defer us.mutex.Unlock()

	us.userToHA1 = n
	return nil
}

// Reload the htdigest's file on a signal. If there is an error, the old data will be kept instead.
// Typically you would use syscall.SIGHUP for the value of "when"
func (us *HtdigestUserStore) ReloadOn(when os.Signal, onbad BadLineHandler) {
	// this is rather common with code in htpasswd, but I don't have a common area...
	c := make(chan os.Signal, 1)
	signal.Notify(c, when)

	go func() {
		for {
			_ = <-c
			log.Printf("Reloading!")
			us.Reload(onbad)
		}
	}()
}

// Create a new UserStore loaded from an Apache style htdigest file.
func NewHtdigestUserStore(filename string, onbad BadLineHandler) (*HtdigestUserStore, error) {
	us := HtdigestUserStore{
		simpleUserStore: simpleUserStore{userToHA1: map[string]string{}},
		filename:        filename,
	}
	if err := us.Reload(onbad); err != nil {
		return nil, err
	} else {
		return &us, nil
	}
}
