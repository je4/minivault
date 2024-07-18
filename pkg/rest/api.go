package rest

import (
	"context"
	"crypto/tls"
	"emperror.dev/errors"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/je4/minivault/v2/pkg/cert"
	"github.com/je4/minivault/v2/pkg/policy"
	"github.com/je4/minivault/v2/pkg/rest/docs"
	"github.com/je4/minivault/v2/pkg/token"
	"github.com/je4/utils/v2/pkg/zLogger"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const BASEPATH = "/api/v1"

//	@title			MiniVault API
//	@version		1.0
//	@description	MiniVault API for managing tokens and certificates
//	@termsOfService	http://swagger.io/terms/

//	@contact.name	Jürgen Enge
//	@contact.url	https://ub.unibas.ch
//	@contact.email	juergen.enge@unibas.ch

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func NewMainController(addr, extAddr, adminAddr, adminBearer string, tlsConfig, adminTLSConfig *tls.Config, tokenManager *token.Manager, policyManager *policy.Manager, certManager cert.Manager, logger zLogger.ZLogger) (*controller, error) {
	u, err := url.Parse(extAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid external address '%s'", extAddr)
	}
	subpath := "/" + strings.Trim(u.Path, "/")

	// programmatically set swagger info
	//docs.SwaggerInfo.Host = strings.TrimRight(fmt.Sprintf("%s:%s", u.Hostname(), u.Port()), " :")
	docs.SwaggerInfo.BasePath = "/" + strings.Trim(subpath+BASEPATH, "/")
	docs.SwaggerInfo.Schemes = []string{"https"}

	gin.SetMode(gin.DebugMode)
	router := gin.Default()

	_logger := logger.With().Str("vaultService", "controller").Logger()
	c := &controller{
		addr:          addr,
		adminAddr:     adminAddr,
		adminBearer:   adminBearer,
		extAddr:       extAddr,
		router:        router,
		subpath:       subpath,
		tokenManager:  tokenManager,
		policyManager: policyManager,
		certManager:   certManager,
		logger:        &_logger,
	}
	if err := c.Init(tlsConfig, adminTLSConfig); err != nil {
		return nil, errors.Wrap(err, "cannot initialize rest controller")
	}
	return c, nil
}

type controller struct {
	server        http.Server
	adminServer   http.Server
	router        *gin.Engine
	addr          string
	extAddr       string
	subpath       string
	adminAddr     string
	adminBearer   string
	tokenManager  *token.Manager
	policyManager *policy.Manager
	logger        zLogger.ZLogger
	certManager   cert.Manager
}

func (ctrl *controller) Init(tlsConfig, adminTLSConfig *tls.Config) error {
	_, port, err := net.SplitHostPort(ctrl.adminAddr)
	if err != nil {
		return errors.Wrapf(err, "invalid admin address '%s'", ctrl.adminAddr)
	}
	ctrl.router.Use(cors.Default(), gin.Recovery(), gin.Logger(), func(ctx *gin.Context) {
		if _, rPort, err := net.SplitHostPort(ctx.Request.Host); err == nil {
			if rPort == port {
				auth := ctx.GetHeader("Authorization")
				if auth != "" {
					if !strings.HasPrefix(auth, "Bearer ") {
						ctx.AbortWithStatusJSON(http.StatusUnauthorized, HTTPResultMessage{Message: "missing bearer token"})
						return
					}
					if strings.TrimPrefix(auth, "Bearer ") != ctrl.adminBearer {
						ctx.AbortWithStatusJSON(http.StatusUnauthorized, HTTPResultMessage{Message: "invalid bearer token"})
						return
					}
					ctx.Set("admin", true)
					return
				}
			}
		}
		ctx.Set("admin", false)
	})

	v1 := ctrl.router.Group(BASEPATH)

	v1.GET("/ping", ctrl.ping)
	v1.POST("/auth/token/create", ctrl.createToken)
	v1.POST("/cert/create", ctrl.createCert)
	v1.GET("/auth/token/get", ctrl.getToken)
	v1.DELETE("/auth/token/delete", ctrl.deleteToken)
	ctrl.router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	ctrl.server = http.Server{
		Addr:      ctrl.addr,
		Handler:   ctrl.router,
		TLSConfig: tlsConfig,
	}

	ctrl.adminServer = http.Server{
		Addr:      ctrl.adminAddr,
		Handler:   ctrl.router,
		TLSConfig: adminTLSConfig,
	}

	return nil
}

func (ctrl *controller) Start(wg *sync.WaitGroup) {
	go func() {
		wg.Add(1)
		defer wg.Done() // let main know we are done cleaning up

		if ctrl.server.TLSConfig == nil {
			fmt.Printf("starting server at http://%s\n", ctrl.addr)
			if err := ctrl.server.ListenAndServe(); err != nil {
				if !errors.Is(err, http.ErrServerClosed) {
					ctrl.logger.Info().Msg("server stopped")
				} else {
					// unexpected error. port in use?
					ctrl.logger.Error().Err(err).Msg("server on '%s' ended")
				}
			}
		} else {
			fmt.Printf("starting server at https://%s\n", ctrl.addr)
			if err := ctrl.server.ListenAndServeTLS("", ""); err != nil {
				if errors.Is(err, http.ErrServerClosed) {
					ctrl.logger.Info().Msg("server stopped")
				} else {
					// unexpected error. port in use?
					ctrl.logger.Error().Err(err).Msg("server on '%s' ended")
				}
			}
		}
		// always returns error. ErrServerClosed on graceful close
	}()
	go func() {
		wg.Add(1)
		defer wg.Done() // let main know we are done cleaning up

		if ctrl.adminServer.TLSConfig == nil {
			fmt.Printf("starting admin server at http://%s\n", ctrl.adminAddr)
			if err := ctrl.adminServer.ListenAndServe(); err != nil {
				if errors.Is(err, http.ErrServerClosed) {
					ctrl.logger.Info().Msg("admin server stopped")
				} else {
					// unexpected error. port in use?
					ctrl.logger.Error().Err(err).Msg("admin server on '%s' ended")
				}
			}
		} else {
			fmt.Printf("starting admin server at https://%s\n", ctrl.adminAddr)
			if err := ctrl.adminServer.ListenAndServeTLS("", ""); err != nil {
				if errors.Is(err, http.ErrServerClosed) {
					ctrl.logger.Info().Msg("admin server stopped")
				} else {
					// unexpected error. port in use?
					ctrl.logger.Error().Err(err).Msg("admin server on '%s' ended")
				}
			}
		}
		// always returns error. ErrServerClosed on graceful close
	}()
}

func (ctrl *controller) Stop() {
	ctrl.server.Shutdown(context.Background())
	ctrl.adminServer.Shutdown(context.Background())
}

func (ctrl *controller) GracefulStop() {
	ctrl.server.Shutdown(context.Background())
	ctrl.adminServer.Shutdown(context.Background())
}

// ping godoc
// @Summary      does pong
// @ID			 get-ping
// @Description  for testing if server is running
// @Tags         mediaserver
// @Security 	 BearerAuth
// @Produce      plain
// @Success      200  {string}  string
// @Router       /ping [get]
func (ctrl *controller) ping(c *gin.Context) {
	if c.GetBool("admin") {
		c.String(http.StatusOK, "admin pong")
	} else {
		c.String(http.StatusOK, "pong")
	}
}

// getToken godoc
// @Summary      lists token contents
// @ID			 get-token-get
// @Description  get token content
// @Tags         mediaserver
// @Security 	 BearerAuth
// @Produce      plain
// @Param 		 X-Vault-Token header string false "token"
// @Success      200  {object}  token.Token
// @Failure      400  {object}  HTTPResultMessage
// @Failure      401  {object}  HTTPResultMessage
// @Failure      404  {object}  HTTPResultMessage
// @Failure      500  {object}  HTTPResultMessage
// @Router       /auth/token/get [get]
func (ctrl *controller) getToken(ctx *gin.Context) {
	tokenID := ctx.GetHeader("X-Vault-Token")
	if tokenID == "" {
		ctx.JSON(http.StatusUnauthorized, HTTPResultMessage{Message: "missing token"})
		return
	}
	token, err := ctrl.tokenManager.Get(tokenID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, HTTPResultMessage{Message: err.Error()})
		return
	}
	if token == nil {
		ctx.JSON(http.StatusNotFound, HTTPResultMessage{Message: "token not found"})
		return
	}
	ctx.JSON(http.StatusOK, token)
}

// getToken godoc
// @Summary      delete token
// @ID			 delete-token-delete
// @Description  delete token content
// @Tags         mediaserver
// @Security 	 BearerAuth
// @Produce      plain
// @Param 		 X-Vault-Token header string false "token"
// @Success      200  {bool}  true
// @Failure      400  {object}  HTTPResultMessage
// @Failure      401  {object}  HTTPResultMessage
// @Failure      404  {object}  HTTPResultMessage
// @Failure      500  {object}  HTTPResultMessage
// @Router       /auth/token/delete [delete]
func (ctrl *controller) deleteToken(ctx *gin.Context) {
	tokenID := ctx.GetHeader("X-Vault-Token")
	if tokenID == "" {
		ctx.JSON(http.StatusUnauthorized, HTTPResultMessage{Message: "missing token"})
		return
	}
	if err := ctrl.tokenManager.Delete(tokenID); err != nil {
		ctx.JSON(http.StatusInternalServerError, HTTPResultMessage{Message: err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, true)
}

// createToken godoc
// @Summary      does pong
// @ID			 post-create-token
// @Description  create a new token
// @Tags         mediaserver
// @Security 	 BearerAuth
// @Produce      plain
// @Param 		 X-Vault-Token header string false "parent token"
// @Param 		 item       body token.CreateStruct true "new token to create"
// @Success      200  {string}  string "token-id"
// @Failure      400  {object}  HTTPResultMessage
// @Failure      401  {object}  HTTPResultMessage
// @Failure      404  {object}  HTTPResultMessage
// @Failure      500  {object}  HTTPResultMessage
// @Router       /auth/token/create [post]
func (ctrl *controller) createToken(ctx *gin.Context) {
	isAdmin := ctx.GetBool("admin")
	createStruct := &token.CreateStruct{}
	if err := ctx.BindJSON(createStruct); err != nil {
		ctx.JSON(http.StatusBadRequest, HTTPResultMessage{Message: err.Error()})
		return
	}
	parentToken := ctx.GetHeader("X-Vault-Token")
	if parentToken == "" && !isAdmin {
		ctx.JSON(http.StatusUnauthorized, HTTPResultMessage{Message: "only admin can create tokens without parent token"})
		return
	}
	token, err := ctrl.tokenManager.Create(parentToken, createStruct)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, HTTPResultMessage{Message: err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, token)
}

type CertResultMessage struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	CA   string `json:"ca"`
}

// createCert godoc
// @Summary      create a new certificate
// @ID			 post-create-cert
// @Description  create a new certificate
// @Tags         mediaserver
// @Security 	 BearerAuth
// @Produce      plain
// @Param 		 X-Vault-Token header string false "token"
// @Param 		 item       body cert.CreateStruct true "new certificate to create"
// @Success      200  {object}  CertResultMessage
// @Failure      400  {object}  HTTPResultMessage
// @Failure      401  {object}  HTTPResultMessage
// @Failure      404  {object}  HTTPResultMessage
// @Failure      500  {object}  HTTPResultMessage
// @Router       /cert/create [post]
func (ctrl *controller) createCert(ctx *gin.Context) {
	isAdmin := ctx.GetBool("admin")
	createStruct := &cert.CreateStruct{}
	if err := ctx.BindJSON(createStruct); err != nil {
		ctx.JSON(http.StatusBadRequest, HTTPResultMessage{Message: err.Error()})
		return
	}
	tokenID := ctx.GetHeader("X-Vault-Token")
	if tokenID == "" && !isAdmin {
		ctx.JSON(http.StatusUnauthorized, HTTPResultMessage{Message: "only admin can create certificates without token"})
		return
	}
	tokenData, err := ctrl.tokenManager.Get(tokenID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, HTTPResultMessage{Message: err.Error()})
		return
	}
	if tokenData == nil {
		ctx.JSON(http.StatusUnauthorized, HTTPResultMessage{Message: "token not found"})
		return
	}
	certType, ok := token.StringType[createStruct.Type]
	if !ok {
		ctx.JSON(http.StatusBadRequest, HTTPResultMessage{Message: fmt.Sprintf("unknown certificate type %s", createStruct.Type)})
		return
	}
	if !slices.Contains([]token.Type{token.TokenServerCert, token.TokenClientCert, token.TokenClientServerCert}, certType) {
		ctx.JSON(http.StatusUnauthorized, HTTPResultMessage{Message: fmt.Sprintf("type %s not allowed to create certificate", certType)})
		return
	}
	if certType != tokenData.GetType() {
		ctx.JSON(http.StatusUnauthorized, HTTPResultMessage{Message: fmt.Sprintf("token type %s does not match certificate type %s", tokenData.GetType(), certType)})
		return
	}
	ttl, err := time.ParseDuration(createStruct.TTL)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, HTTPResultMessage{Message: fmt.Sprintf("cannot parse duration %s: %s", createStruct.TTL, err.Error())})
		return
	}
	cert, key, err := ctrl.certManager.Create(
		slices.Contains([]token.Type{token.TokenClientServerCert, token.TokenClientCert}, certType),
		slices.Contains([]token.Type{token.TokenClientServerCert, token.TokenServerCert}, certType),
		createStruct.URIs,
		[]net.IP{},
		createStruct.DNSNames,
		ttl,
	)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, HTTPResultMessage{Message: fmt.Sprintf("cannot create certificate: %s", err.Error())})
		return
	}
	ctx.JSON(http.StatusOK, CertResultMessage{Cert: string(cert), Key: string(key)})
}
