package main

import (
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/je4/certloader/v2/pkg/loader"
	"github.com/je4/minivault/v2/config"
	"github.com/je4/minivault/v2/pkg/badgerStore"
	"github.com/je4/minivault/v2/pkg/localca"
	"github.com/je4/minivault/v2/pkg/policy"
	"github.com/je4/minivault/v2/pkg/rest"
	"github.com/je4/minivault/v2/pkg/token"
	"github.com/je4/trustutil/v2/pkg/certutil"
	"github.com/je4/utils/v2/pkg/zLogger"
	ublogger "gitlab.switch.ch/ub-unibas/go-ublogger"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

var configfile = flag.String("config", "", "location of toml configuration file")

func main() {
	flag.Parse()

	var cfgFS fs.FS
	var cfgFile string
	if *configfile != "" {
		cfgFS = os.DirFS(filepath.Dir(*configfile))
		cfgFile = filepath.Base(*configfile)
	} else {
		cfgFS = config.ConfigFS
		cfgFile = "minivault.toml"
	}

	conf := &MiniVaultConfig{
		LocalAddr: "localhost:8443",
		//ResolverTimeout: config.Duration(10 * time.Minute),
		ExternalAddr: "https://localhost:8443",
		LogLevel:     "DEBUG",
	}
	if err := LoadMiniVaultConfig(cfgFS, cfgFile, conf); err != nil {
		log.Fatalf("cannot load toml from [%v] %s: %v", cfgFS, cfgFile, err)
	}

	// create logger instance
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("cannot get hostname: %v", err)
	}

	var loggerTLSConfig *tls.Config
	var loggerLoader io.Closer
	if conf.Log.Stash.TLS != nil {
		loggerTLSConfig, loggerLoader, err = loader.CreateClientLoader(conf.Log.Stash.TLS, nil)
		if err != nil {
			log.Fatalf("cannot create client loader: %v", err)
		}
		defer loggerLoader.Close()
	}

	_logger, _logstash, _logfile := ublogger.CreateUbMultiLoggerTLS(conf.Log.Level, conf.Log.File,
		ublogger.SetDataset(conf.Log.Stash.Dataset),
		ublogger.SetLogStash(conf.Log.Stash.LogstashHost, conf.Log.Stash.LogstashPort, conf.Log.Stash.Namespace, conf.Log.Stash.LogstashTraceLevel),
		ublogger.SetTLS(conf.Log.Stash.TLS != nil),
		ublogger.SetTLSConfig(loggerTLSConfig),
	)
	if _logstash != nil {
		defer _logstash.Close()
	}
	if _logfile != nil {
		defer _logfile.Close()
	}

	l2 := _logger.With().Timestamp().Str("host", hostname).Str("addr", conf.LocalAddr).Logger() //.Output(output)
	var logger zLogger.ZLogger = &l2

	var tokenStore token.Store
	switch conf.TokenStore {
	case "badger":
		if conf.BadgerStore == nil {
			logger.Panic().Msg("badger store configuration missing")
		}
		var key []byte
		if conf.BadgerStore.HexKey != "" {
			key, err = hex.DecodeString(string(conf.BadgerStore.HexKey))
			if err != nil {
				logger.Fatal().Msgf("cannot decode hex key '%s': %v", conf.BadgerStore.HexKey, err)
			}
		}
		tokenStore, err = badgerStore.NewBadgerStore(conf.BadgerStore.Folder, key, conf.BadgerStore.CacheSize)
		if err != nil {
			logger.Fatal().Msgf("cannot create badger store: %v", err)
		}
	default:
		logger.Panic().Msgf("unknown token store '%s'", conf.TokenStore)
	}
	defer tokenStore.Close()

	tokenManager := token.NewManager(tokenStore, conf.TokenXOR, conf.RndSize)

	var wg = &sync.WaitGroup{}

	policyManager := policy.NewManager(conf.PolicyFile, logger)
	if err := policyManager.Start(wg); err != nil {
		logger.Panic().Err(err).Msg("cannot start policy manager")
	}

	ca, key, err := certutil.CertificateKeyFromPEM([]byte(conf.CA), []byte(conf.CAKey), []byte(conf.CAPassword))
	if err != nil {
		logger.Fatal().Err(err).Msg("cannot decode ca")
	}

	certManager := localca.NewManager(ca, key, conf.CertName, certutil.DefaultKeyType, logger)

	webTLSConfig, webLoader, err := loader.CreateServerLoader(false, &conf.WebTLS, nil, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("cannot create server loader")
	}
	defer webLoader.Close()

	adminTLSConfig, adminLoader, err := loader.CreateServerLoader(false, &conf.AdminTLS, nil, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("cannot create server loader")
	}
	defer adminLoader.Close()

	ctrl, err := rest.NewMainController(
		conf.LocalAddr,
		conf.ExternalAddr,
		string(conf.AdminAddr),
		string(conf.AdminBearer),
		webTLSConfig,
		adminTLSConfig,
		tokenManager,
		policyManager,
		certManager,
		logger)
	if err != nil {
		logger.Fatal().Msgf("cannot create controller: %v", err)
	}
	ctrl.Start(wg)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	fmt.Println("press ctrl+c to stop server")
	s := <-done
	fmt.Println("Got signal:", s)

	ctrl.GracefulStop()
	policyManager.Stop()
	wg.Wait()
}
