package git

import (
	"sync"
	"time"
)

// RepoService is the repository service that runs in background and
// periodic pull from the repository.
type RepoService struct {
	repo    *Repo
	running bool          // whether service is running.
	halt    chan struct{} // channel to notify service to halt and stop pulling.
	exit    chan struct{} // channel to notify on exit.
}

// Start starts a new RepoService in background and adds it to monitor.
func Start(repo *Repo) {
	service := &RepoService{
		repo,
		true,
		make(chan struct{}),
		make(chan struct{}),
	}

	// start service
	go func(s *RepoService) {
		for {
			// if service is halted
			if !s.running {
				// notify exit channel
				service.exit <- struct{}{}
				break
			}
			time.Sleep(repo.Interval)

			err := repo.Pull()
			if err != nil {
				logger().Println(err)
			}
		}
	}(service)

	// add to monitor to enable halting
	Monitor.add(service)
}

// monitor monitors running services (RepoService)
// and can halt them.
type monitor struct {
	services []*RepoService
	sync.Mutex
}

// add adds a new service to the monitor.
func (m *monitor) add(service *RepoService) {
	m.Lock()
	defer m.Unlock()

	m.services = append(m.services, service)

	// start a goroutine to listen for halt signal
	service.running = true
	go func(r *RepoService) {
		<-r.halt
		r.running = false
	}(service)
}

// Stop stops at most `limit` currently running services that is pulling from git repo at
// repoURL. It returns list of exit channels for the services. A wait for message on the
// channels guarantees exit. If limit is less than zero, it is ignored.
// TODO find better ways to identify repos
func (m *monitor) Stop(repoURL string, limit int) []chan struct{} {
	m.Lock()
	defer m.Unlock()

	var chans []chan struct{}

	// locate services
	for i, j := 0, 0; i < len(m.services) && ((limit >= 0 && j < limit) || limit < 0); i++ {
		s := m.services[i]
		if s.repo.URL == repoURL {
			// send halt signal
			s.halt <- struct{}{}
			chans = append(chans, s.exit)
			j++
			m.services[i] = nil
		}
	}

	// remove them from services list
	services := m.services[:0]
	for _, s := range m.services {
		if s != nil {
			services = append(services, s)
		}
	}
	m.services = services
	return chans
}

// StopAndWait is similar to stop but it waits for the services to terminate before
// returning.
func (m *monitor) StopAndWait(repoUrl string, limit int) {
	chans := m.Stop(repoUrl, limit)
	for _, c := range chans {
		<-c
	}
}
