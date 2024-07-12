package main

import (
	"emperror.dev/errors"
	"github.com/BurntSushi/toml"
	loaderConfig "github.com/je4/trustutil/v2/pkg/config"
	"github.com/je4/utils/v2/pkg/config"
	"github.com/je4/utils/v2/pkg/zLogger"
	"io/fs"
	"os"
	"strings"
)

type BadgerStoreConfig struct {
	Folder    string           `toml:"folder"`
	HexKey    config.EnvString `toml:"hexkey"`
	CacheSize int64            `toml:"cachesize"`
}

type MiniVaultConfig struct {
	LocalAddr    string                 `toml:"localaddr"`
	ExternalAddr string                 `toml:"externaladdr"`
	WebTLS       loaderConfig.TLSConfig `toml:"webtls"`
	PolicyFile   string                 `toml:"policyfile"`
	TokenXOR     uint64                 `toml:"tokenxor"`
	LogFile      string                 `toml:"logfile"`
	LogLevel     string                 `toml:"loglevel"`
	Log          zLogger.Config         `toml:"log"`
	TokenStore   string                 `toml:"tokenstore"`
	BadgerStore  *BadgerStoreConfig     `toml:"badgerstore"`
}

func LoadMiniVaultConfig(fSys fs.FS, fp string, conf *MiniVaultConfig) error {
	if _, err := fs.Stat(fSys, fp); err != nil {
		path, err := os.Getwd()
		if err != nil {
			return errors.Wrap(err, "cannot get current working directory")
		}
		fSys = os.DirFS(path)
		fp = "minivault.toml"
	}
	data, err := fs.ReadFile(fSys, fp)
	if err != nil {
		return errors.Wrapf(err, "cannot read file [%v] %s", fSys, fp)
	}
	_, err = toml.Decode(string(data), conf)
	if err != nil {
		return errors.Wrapf(err, "error loading config file %v", fp)
	}
	conf.TokenStore = strings.ToLower(conf.TokenStore)
	return nil
}
