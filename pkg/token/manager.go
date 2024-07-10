package token

func NewManager(store Store) *Manager {
	return &Manager{store: store}
}

type Manager struct {
	store Store
}
