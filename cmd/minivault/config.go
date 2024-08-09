package main

import (
	"crypto/x509/pkix"
	"emperror.dev/errors"
	"github.com/BurntSushi/toml"
	"github.com/je4/certloader/v2/pkg/loader"
	"github.com/je4/utils/v2/pkg/config"
	"github.com/je4/utils/v2/pkg/stashconfig"
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
	LocalAddr    string             `toml:"localaddr"`
	AdminAddr    config.EnvString   `toml:"adminaddr"`
	AdminBearer  config.EnvString   `toml:"adminbearer"`
	ExternalAddr string             `toml:"externaladdr"`
	CA           config.EnvString   `toml:"ca"`
	CAKey        config.EnvString   `toml:"cakey"`
	CAPassword   config.EnvString   `toml:"capassword"`
	CertName     *pkix.Name         `toml:"certname"`
	WebTLS       loader.Config      `toml:"webtls"`
	AdminTLS     loader.Config      `toml:"admintls"`
	PolicyFile   string             `toml:"policyfile"`
	TokenXOR     uint64             `toml:"tokenxor"`
	RndSize      int                `toml:"rndsize"`
	LogFile      string             `toml:"logfile"`
	LogLevel     string             `toml:"loglevel"`
	Log          stashconfig.Config `toml:"log"`
	TokenStore   string             `toml:"tokenstore"`
	BadgerStore  *BadgerStoreConfig `toml:"badgerstore"`
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
