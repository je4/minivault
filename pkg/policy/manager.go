package policy

import (
	"emperror.dev/errors"
	"github.com/BurntSushi/toml"
	"github.com/fsnotify/fsnotify"
	"github.com/je4/utils/v2/pkg/zLogger"
	"sync"
)

func NewManager(configFile string, logger zLogger.ZLogger) *Manager {
	return &Manager{
		policies:   make(map[string]*Policy),
		configFile: configFile,
		logger:     logger,
		stop:       make(chan bool),
	}
}

type Manager struct {
	sync.RWMutex
	policies   map[string]*Policy
	configFile string
	logger     zLogger.ZLogger
	stop       chan bool
}

func (m *Manager) Start(wg *sync.WaitGroup) error {
	wg.Add(1)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return errors.Wrap(err, "cannot create watcher")
	}
	if err := watcher.Add(m.configFile); err != nil {
		return errors.Wrapf(err, "cannot watch file %s", m.configFile)
	}
	if err := m.load(); err != nil {
		return errors.Wrap(err, "cannot load policies")
	}
	go func() {
		defer wg.Done()
		defer watcher.Close()
		for {
			select {
			case <-m.stop:
				m.logger.Info().Msg("stop watching policies")
				return
			case event := <-watcher.Events:
				if event.Has(fsnotify.Write) {
					if err := m.load(); err != nil {
						m.logger.Error().Err(err).Msg("cannot load policies")
					}
				}
			case err := <-watcher.Errors:
				m.logger.Error().Err(err).Msg("watcher error")
			}
		}
	}()
	return nil
}

func (m *Manager) Stop() {
	m.stop <- true
}

type policyConfig struct {
	Policies []*Policy `toml:"policy"`
}

func (m *Manager) load() error {
	m.Lock()
	defer m.Unlock()
	var policies = policyConfig{}
	m.logger.Info().Msgf("loading policies from %s", m.configFile)
	if _, err := toml.DecodeFile(m.configFile, &policies); err != nil {
		return errors.Wrapf(err, "cannot decode file %s", m.configFile)
	}
	m.policies = make(map[string]*Policy)
	for _, p := range policies.Policies {
		m.policies[p.Name] = p
	}
	return nil
}

func (m *Manager) Get(id string) (*Policy, bool) {
	m.RLock()
	defer m.RUnlock()
	p, ok := m.policies[id]
	return p, ok
}
