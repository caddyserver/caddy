package git

import (
	"sync"

	"github.com/mholt/caddy/middleware/git/gitos"
)

// repoService is the service that runs in background and periodically
// pull from the repository.
type repoService struct {
	repo   *Repo
	ticker gitos.Ticker  // ticker to tick at intervals
	halt   chan struct{} // channel to notify service to halt and stop pulling.
}

// Start starts a new background service to pull periodically.
func Start(repo *Repo) {
	service := &repoService{
		repo,
		gos.NewTicker(repo.Interval),
		make(chan struct{}),
	}
	go func(s *repoService) {
		for {
			select {
			case <-s.ticker.C():
				err := repo.Pull()
				if err != nil {
					Logger().Println(err)
				}
			case <-s.halt:
				s.ticker.Stop()
				return
			}
		}
	}(service)

	// add to services to make it stoppable
	Services.add(service)
}

// services stores all repoServices
type services struct {
	services []*repoService
	sync.Mutex
}

// add adds a new service to list of services.
func (s *services) add(r *repoService) {
	s.Lock()
	defer s.Unlock()

	s.services = append(s.services, r)
}

// Stop stops at most `limit` running services pulling from git repo at
// repoURL. It waits until the service is terminated before returning.
// If limit is less than zero, it is ignored.
// TODO find better ways to identify repos
func (s *services) Stop(repoURL string, limit int) {
	s.Lock()
	defer s.Unlock()

	// locate repos
	for i, j := 0, 0; i < len(s.services) && ((limit >= 0 && j < limit) || limit < 0); i++ {
		service := s.services[i]
		if service.repo.URL == repoURL {
			// send halt signal
			service.halt <- struct{}{}
			s.services[i] = nil
			j++
		}
	}

	// remove them from repos list
	services := s.services[:0]
	for _, s := range s.services {
		if s != nil {
			services = append(services, s)
		}
	}
	s.services = services
}
