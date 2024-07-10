package badgerStore

import (
	"context"
	"emperror.dev/errors"
	"github.com/dgraph-io/badger/v4"
	"github.com/je4/minivault/v2/pkg/token"
	"time"
)

func NewBadgerStore(badgerFolder string, key []byte, cacheSize int64) (*BadgerStore, error) {
	options := badger.DefaultOptions(badgerFolder)
	if len(key) != 0 {
		options = options.WithEncryptionKey(key)
	}
	if cacheSize != 0 {
		options = options.WithIndexCacheSize(cacheSize)
	}
	db, err := badger.Open(options)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot open badger db in folder %s", badgerFolder)
	}
	return &BadgerStore{db: db}, nil
}

type BadgerStore struct {
	db *badger.DB
}

func (b *BadgerStore) Close() error {
	return errors.WithStack(b.db.Close())
}

func (b *BadgerStore) Get(ctx context.Context, tokenID string) ([]byte, error) {
	var t []byte
	if err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(tokenID))
		if err != nil {
			return errors.Wrapf(err, "cannot get token %s", tokenID)
		}
		if err := item.Value(func(val []byte) error {
			t = val
			return nil
		}); err != nil {
			return errors.Wrapf(err, "cannot get value for token %s", tokenID)
		}
		return nil
	}); err != nil {
		return nil, errors.Wrapf(err, "cannot view badger db")
	}
	return t, nil
}

func (b *BadgerStore) Put(_ context.Context, tokenID string, token []byte, ttl time.Duration) error {
	if err := b.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(tokenID), token)
		if ttl != 0 {
			e = e.WithTTL(ttl)
		}
		if err := txn.SetEntry(e); err != nil {
			return errors.Wrapf(err, "cannot set entry for token %s", tokenID)
		}
		return nil
	}); err != nil {
		return errors.Wrapf(err, "cannot update badger db")
	}
	return nil
}

func (b *BadgerStore) Delete(ctx context.Context, tokenID string) error {
	if err := b.db.Update(func(txn *badger.Txn) error {
		if err := txn.Delete([]byte(tokenID)); err != nil {
			return errors.Wrapf(err, "cannot delete token %s", tokenID)
		}
		return nil
	}); err != nil {
		return errors.Wrapf(err, "cannot update badger db")
	}
	return nil
}

var _ token.Store = (*BadgerStore)(nil)
