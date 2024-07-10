package web

import (
	"context"
	"crypto/tls"
	"emperror.dev/errors"
	"fmt"
	"github.com/bluele/gcache"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/je4/mediaserveraction/v2/pkg/actionCache"
	"github.com/je4/mediaservermain/v2/data/web/static"
	mediaserverproto "github.com/je4/mediaserverproto/v2/pkg/mediaserver/proto"
	"github.com/je4/utils/v2/pkg/zLogger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

type itemIdentifier struct {
	collection string
	signature  string
}

func NewMainController(addr, extAddr string, tlsConfig *tls.Config, logger zLogger.ZLogger) (*mainController, error) {
	u, err := url.Parse(extAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid external address '%s'", extAddr)
	}
	subpath := "/" + strings.Trim(u.Path, "/")

	gin.SetMode(gin.DebugMode)
	router := gin.Default()

	_logger := logger.With().Str("httpService", "mainController").Logger()
	parts := strings.SplitN(iiifBaseAction, "/", 2)
	if len(parts) < 1 {
		return nil, errors.New("invalid iiifBaseAction")
	}
	action := parts[0]
	params := ""
	if len(parts) > 1 {
		params = parts[1]
	}

	c := &mainController{
		addr:                   addr,
		extAddr:                extAddr,
		jwtAlgs:                jwtAlgs,
		iiif:                   iiif,
		iiifPrefix:             iiifPrefix,
		iiifBaseAction:         action,
		iiifBaseActionParams:   params,
		router:                 router,
		subpath:                subpath,
		logger:                 &_logger,
		dbClient:               dbClient,
		actionControllerClient: actionControllerClient,
		actionParams:           map[string][]string{},
		vfs:                    vfs,
		actionTemplates:        gcache.New(100).LRU().Expiration(actionTemplateTimeout).Build(),
		itemCache: gcache.New(itemCacheSize).
			LRU().Expiration(cacheTimout).
			LoaderFunc(func(key any) (any, error) {
				it, ok := key.(itemIdentifier)
				if !ok {
					return nil, errors.Errorf("invalid key type %T", key)
				}
				resp, err := dbClient.GetItem(context.Background(), &mediaserverproto.ItemIdentifier{
					Collection: it.collection,
					Signature:  it.signature,
				})
				if err != nil {
					if stat, ok := status.FromError(err); ok && stat.Code() == codes.NotFound {
						return nil, gcache.KeyNotFoundError
					}
					return nil, errors.Wrapf(err, "cannot get item %s/%s", it.collection, it.signature)
				}
				return resp, nil
			}).
			Build(),
		collectionCache: gcache.New(collectionCachesize).
			LRU().Expiration(cacheTimout).
			LoaderFunc(func(key any) (any, error) {
				collectionName, ok := key.(string)
				if !ok {
					return nil, errors.Errorf("invalid key type %T", key)
				}
				resp, err := dbClient.GetCollection(context.Background(), &mediaserverproto.CollectionIdentifier{
					Collection: collectionName,
				})
				if err != nil {
					if stat, ok := status.FromError(err); ok && stat.Code() == codes.NotFound {
						return nil, gcache.KeyNotFoundError
					}
					return nil, errors.Wrapf(err, "cannot get collection %s", collectionName)
				}
				return resp, nil
			}).
			Build(),
	}
	if err := c.Init(tlsConfig); err != nil {
		return nil, errors.Wrap(err, "cannot initialize rest controller")
	}
	return c, nil
}

type mainController struct {
	server                 http.Server
	router                 *gin.Engine
	addr                   string
	subpath                string
	logger                 zLogger.ZLogger
	dbClient               mediaserverproto.DatabaseClient
	actionControllerClient mediaserverproto.ActionClient
	actionParams           map[string][]string
	itemCache              gcache.Cache
	collectionCache        gcache.Cache
	vfs                    fs.FS
	jwtAlgs                []string
	iiif                   string
	iiifPrefix             string
	extAddr                string
	iiifBaseAction         string
	iiifBaseActionParams   string
	actionTemplates        gcache.Cache
}

func (ctrl *mainController) Init(tlsConfig *tls.Config) error {
	ctrl.router.Use(cors.Default())
	ctrl.router.StaticFS("/static", http.FS(static.FS))
	ctrl.router.GET("/iiif/:version/:collection/:signature/*params", ctrl.iiifAction)
	ctrl.router.GET("/:collection/:signature/:action", ctrl.action)
	ctrl.router.GET("/:collection/:signature/:action/*params", ctrl.action)

	ctrl.server = http.Server{
		Addr:      ctrl.addr,
		Handler:   ctrl.router,
		TLSConfig: tlsConfig,
	}

	return nil
}

func (ctrl *mainController) getParams(mediaType string, action string) ([]string, error) {
	sig := fmt.Sprintf("%s::%s", mediaType, action)
	if params, ok := ctrl.actionParams[sig]; ok {
		return params, nil
	}
	resp, err := ctrl.actionControllerClient.GetParams(context.Background(), &mediaserverproto.ParamsParam{
		Type:   mediaType,
		Action: action,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "cannot get params for %s::%s", mediaType, action)
	}
	ctrl.logger.Debug().Msgf("params for %s::%s: %v", mediaType, action, resp.GetValues())
	ctrl.actionParams[sig] = resp.GetValues()
	return resp.GetValues(), nil
}

func (ctrl *mainController) getItem(collection, signature string) (*mediaserverproto.Item, error) {
	itemAny, err := ctrl.itemCache.Get(itemIdentifier{collection: collection, signature: signature})
	if err != nil {
		return nil, errors.Wrapf(err, "cannot get item %s/%s", collection, signature)
	}
	item, ok := itemAny.(*mediaserverproto.Item)
	if !ok {
		return nil, errors.Errorf("invalid item type %T", itemAny)
	}
	return item, nil
}

func (ctrl *mainController) getCollection(collection string) (*mediaserverproto.Collection, error) {
	itemAny, err := ctrl.collectionCache.Get(collection)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot get item %s", collection)
	}
	coll, ok := itemAny.(*mediaserverproto.Collection)
	if !ok {
		return nil, errors.Errorf("invalid item type %T", itemAny)
	}
	return coll, nil
}

func (ctrl *mainController) Start(wg *sync.WaitGroup) {
	go func() {
		wg.Add(1)
		defer wg.Done() // let main know we are done cleaning up

		if ctrl.server.TLSConfig == nil {
			fmt.Printf("starting server at http://%s\n", ctrl.addr)
			if err := ctrl.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				// unexpected error. port in use?
				fmt.Errorf("server on '%s' ended: %v", ctrl.addr, err)
			}
		} else {
			fmt.Printf("starting server at https://%s\n", ctrl.addr)
			if err := ctrl.server.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
				// unexpected error. port in use?
				fmt.Errorf("server on '%s' ended: %v", ctrl.addr, err)
			}
		}
		// always returns error. ErrServerClosed on graceful close
	}()
}

func (ctrl *mainController) Stop() {
	ctrl.server.Shutdown(context.Background())
}

func (ctrl *mainController) GracefulStop() {
	ctrl.server.Shutdown(context.Background())
}

var isUrlRegexp = regexp.MustCompile(`^[a-z]+://`)

var pathRegexp = regexp.MustCompile(`"/?(.+?)/(.+?)/(.+)?(/(.+?))?$`)

func (ctrl *mainController) checkAccess(collection, signature, action, paramStr, token string) error {
	item, err := ctrl.getItem(collection, signature)
	if err != nil {
		return errors.Wrapf(err, "cannot get item %s/%s", collection, signature)
	}
	// public items are always allowed
	if item.GetPublic() {
		return nil
	}
	// check whether it's a public action
	if publicActions := item.GetPublicActions(); len(publicActions) > 0 {
		actionParams, err := ctrl.getParams(item.GetMetadata().GetType(), action)
		if err != nil {
			return errors.Wrapf(err, "cannot get params for %s::%s", item.GetMetadata().GetType(), action)
		}
		ap := actionCache.ActionParams{}
		ap.SetString(paramStr, actionParams)
		fullAction := fmt.Sprintf("%s/%s", action, ap.String())
		if slices.Contains(publicActions, fullAction) {
			return nil
		}
	}
	if token == "" {
		return errors.New("no token provided")
	}
	coll, err := ctrl.getCollection(collection)
	if err != nil {
		return errors.Wrapf(err, "cannot get collection %s", collection)
	}
	jwtKey := coll.GetJwtkey()
	if jwtKey == "" {
		return errors.New("no jwt key in collection configured. please ask administrator")
	}
	jwtToken, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		tokenAlg := token.Method.Alg()
		for _, alg := range ctrl.jwtAlgs {
			if tokenAlg == alg {
				return []byte(jwtKey), nil
			}
		}
		return nil, fmt.Errorf("alg: %v not supported", tokenAlg)
	})
	if err != nil {
		return errors.Wrapf(err, "cannot parse jwt token '%s'", token)
	}
	if !jwtToken.Valid {
		return errors.Errorf("invalid jwt token '%s'", token)
	}
	subject, err := jwtToken.Claims.GetSubject()
	if err != nil {
		return errors.Wrapf(err, "cannot get subject from jwt token '%s'", token)
	}
	_subject := strings.Trim(fmt.Sprintf("%s/%s/%s/%s", collection, signature, action, paramStr), "/")
	if subject != _subject {
		return errors.Errorf("invalid subject '%s' in jwt token - should be '%s'", subject, _subject)
	}

	return nil
}
func (ctrl *mainController) iiifAction(c *gin.Context) {
	action := "iiif"
	version := c.Param("version")
	versionInt, err := strconv.Atoi(version)
	if err != nil {
		ctrl.logger.Error().Err(err).Msgf("invalid IIIF version '%s'", version)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("invalid IIIF version '%s'", version),
		})
		c.Abort()
		return
	}
	collection := c.Param("collection")
	signature := c.Param("signature")
	paramStr := c.Param("params")
	token := c.Query("token")
	ctrl.logger.Debug().Msgf("collection: %s, signature: %s, action: %s, params: %s", collection, signature, action, paramStr)

	item, err := ctrl.getItem(collection, signature)
	if err != nil {
		httpStatus := http.StatusInternalServerError
		if errors.Is(err, gcache.KeyNotFoundError) {
			httpStatus = http.StatusNotFound
		}
		ctrl.logger.Error().Err(err).Msgf("cannot get item %s/%s", collection, signature)
		c.JSON(httpStatus, gin.H{
			"error": fmt.Sprintf("cannot get item %s/%s: %v", collection, signature, err),
		})
		c.Abort()
		return
	}
	if err := ctrl.checkAccess(collection, signature, action, paramStr, token); err != nil {
		ctrl.logger.Info().Err(err).Msgf("access denied for %s/%s/%s/%s", collection, signature, action, paramStr)
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("access denied for %s/%s/%s/%s: %v", collection, signature, action, paramStr, err)})
		c.Abort()
		return
	}
	cache, err := ctrl.dbClient.GetCache(context.Background(), &mediaserverproto.CacheRequest{
		Identifier: &mediaserverproto.ItemIdentifier{
			Collection: collection,
			Signature:  signature,
		},
		Action: ctrl.iiifBaseAction,
		Params: ctrl.iiifBaseActionParams,
	})
	if err != nil {
		stat, ok := status.FromError(err)
		if !ok || stat.Code() != codes.NotFound {
			ctrl.logger.Error().Err(err).Msgf("cannot get cache for %s/%s/%s/%s", collection, signature, ctrl.iiifBaseAction, ctrl.iiifBaseActionParams)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get cache for %s/%s/%s/%s: %v", collection, signature, ctrl.iiifBaseAction, ctrl.iiifBaseActionParams, err),
			})
			return
		}
		coll, err := ctrl.dbClient.GetCollection(context.Background(), &mediaserverproto.CollectionIdentifier{
			Collection: collection,
		})
		if err != nil {
			ctrl.logger.Error().Err(err).Msgf("cannot get collection %s", collection)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get collection %s: %v", collection, err),
			})
			return
		}

		var params = actionCache.ActionParams{}
		allowedParams, err := ctrl.getParams(item.GetMetadata().GetType(), ctrl.iiifBaseAction)
		if err != nil {
			ctrl.logger.Error().Err(err).Msgf("cannot get params for %s::%s", item.GetMetadata().GetType(), action)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get params for %s::%s: %v", item.GetMetadata().GetType(), action, err),
			})
			return
		}
		params.SetString(ctrl.iiifBaseActionParams, allowedParams)

		// cache not found, create it
		cache, err = ctrl.actionControllerClient.Action(context.Background(), &mediaserverproto.ActionParam{
			Item:    item,
			Action:  ctrl.iiifBaseAction,
			Params:  params,
			Storage: coll.GetStorage(),
		})
		if err != nil {
			ctrl.logger.Error().Err(err).Msgf("cannot get cache for %s/%s/%s: %v", collection, signature, action, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get cache for %s/%s/%s: %v", collection, signature, action, err),
			})
			return
		}
		if cache == nil {
			ctrl.logger.Error().Msgf("cannot get cache for %s/%s/%s: no cache", collection, signature, action)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get cache for %s/%s/%s: no cache", collection, signature, action),
			})
			return
		}
	}
	fullpath := cache.GetMetadata().GetPath()
	/*itemCache, err := ctrl.dbClient.GetCache(context.Background(), &mediaserverproto.CacheRequest{
		Identifier: &mediaserverproto.ItemIdentifier{
			Collection: collection,
			Signature:  signature,
		},
		Action: "item",
	})
	if err != nil {
		ctrl.logger.Error().Err(err).Msgf("cannot get item cache for %s/%s", collection, signature)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("cannot get item cache for %s/%s: %v", collection, signature, err),
		})
		return
	}
	fullpath := itemCache.GetMetadata().GetPath()
	*/
	if !isUrlRegexp.MatchString(fullpath) {
		stor := cache.GetMetadata().GetStorage()
		//stor := itemCache.GetMetadata().GetStorage()
		if stor == nil {
			ctrl.logger.Error().Msgf("no storage defined for %s/%s/%s/%s", collection, signature, action, paramStr)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("no storage defined for %s/%s/%s/%s", collection, signature, action, paramStr),
			})
			return
		}
		fullpath = stor.GetFilebase() + "/" + fullpath
	}
	iifPath := strings.Replace(strings.TrimPrefix(fullpath, ctrl.iiifPrefix), "/", "$$", -1)

	u, err := url.JoinPath(ctrl.iiif, strconv.Itoa(versionInt), iifPath, paramStr)
	if err != nil {
		ctrl.logger.Error().Err(err).Msgf("cannot join url '%s' and [%v]", ctrl.iiif, []string{iifPath, paramStr})
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("cannot join url '%s' and [%v]: %v", ctrl.iiif, []string{iifPath, paramStr}, err),
		})
		c.Abort()
		return
	}
	ctrl.logger.Debug().Msgf("proxy to %s", u)
	req2, err := http.NewRequest("GET", u, nil)
	if err != nil {
		fmt.Printf("cantaloupe request error: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("cannot create new request to %s: %v", u, err),
		})
		c.Abort()
		return
	}

	urlStr, err := url.JoinPath(ctrl.extAddr)
	if err != nil {
		ctrl.logger.Error().Err(err).Msgf("cannot join url %s %s", ctrl.extAddr, "iiif")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("cannot join url %s %s: %v", ctrl.extAddr, "iiif", err),
		})
		c.Abort()
		return
	}
	p, err := url.Parse(urlStr)
	if err != nil {
		ctrl.logger.Error().Err(err).Msgf("cannot parse url %s", urlStr)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("cannot parse url %s: %v", urlStr, err),
		})
		c.Abort()
		return
	}

	// build headers to send cantaloupe the real url's to use
	//proto, host, port := ms.getProtoHostPort(req)
	req2.Header.Add("X-Forwarded-Proto", p.Scheme)
	req2.Header.Add("X-Forwarded-Host", p.Hostname())
	req2.Header.Add("X-Forwarded-Port", p.Port())
	// req2.Header.Add("X-Forwarded-Path", SingleJoiningSlash(baseurl.RawPath, SingleJoiningSlash(ms.iiifPrefix, signature+"/"+newtoken)+"/"))
	req2.Header.Add("X-Forwarded-Path", p.Path)
	req2.Header.Add("X-Forwarded-For", c.Request.RemoteAddr[:strings.IndexByte(c.Request.RemoteAddr, ':')])
	req2.Header.Add("X-Forwarded-ID", fmt.Sprintf("%s/%s", collection, signature))

	for k, v := range req2.Header {
		ctrl.logger.Debug().Msgf("header %s: %v", k, v)
	}
	client := &http.Client{}
	rs, err := client.Do(req2)
	if err != nil {
		ctrl.logger.Error().Err(err).Msgf("cannot proxy to iiif server: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("cannot proxy to iiif server: %v", err),
		})
		c.Abort()
		return
	}

	defer rs.Body.Close()

	for k, v := range rs.Header {
		for _, vv := range v {
			c.Header(k, vv)
		}
	}

	c.Writer.WriteHeader(rs.StatusCode)
	c.Writer.WriteHeaderNow()
	if _, err := io.Copy(c.Writer, rs.Body); err != nil {
		ctrl.logger.Error().Err(err).Msgf("cannot copy from iiif server: %v", err)
		return
	}
	return
}

func (ctrl *mainController) doTemplate(c *gin.Context, tpl *template.Template, collection, signature string) {
	data := map[string]string{
		"BaseURL":    ctrl.extAddr,
		"Collection": collection,
		"Signature":  signature,
	}
	c.Header("Content-Type", "text/html")
	if err := tpl.Execute(c.Writer, data); err != nil {
		ctrl.logger.Error().Err(err).Msgf("cannot execute template %v/%s", ctrl.vfs, tpl)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("cannot execute template %v/%s: %v", ctrl.vfs, tpl, err),
		})
		return
	}
	return
}

var dataRegexp = regexp.MustCompile(`(?s)^data:([^\/]+\/[^,]+),(.*)$`)

func (ctrl *mainController) action(c *gin.Context) {
	collection := c.Param("collection")
	signature := c.Param("signature")
	action := c.Param("action")
	paramStr := c.Param("params")
	token := c.Query("token")
	ctrl.logger.Debug().Msgf("collection: %s, signature: %s, action: %s, params: %s", collection, signature, action, paramStr)

	item, err := ctrl.getItem(collection, signature)
	if err != nil {
		httpStatus := http.StatusInternalServerError
		stat, ok := status.FromError(err)
		if !ok || stat.Code() != codes.NotFound {
			httpStatus = http.StatusNotFound
		}
		ctrl.logger.Error().Err(err).Msgf("cannot get item %s/%s", collection, signature)
		c.JSON(httpStatus, gin.H{
			"error": fmt.Sprintf("cannot get item %s/%s: %v", collection, signature, err),
		})
		c.Abort()
		return
	}
	if err := ctrl.checkAccess(collection, signature, action, paramStr, token); err != nil {
		ctrl.logger.Info().Err(err).Msgf("access denied for %s/%s/%s/%s", collection, signature, action, paramStr)
		c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("access denied for %s/%s/%s/%s: %v", collection, signature, action, paramStr, err)})
		c.Abort()
		return
	}
	if action == "metadata" {
		metadata, err := ctrl.dbClient.GetItemMetadata(context.Background(), &mediaserverproto.ItemIdentifier{
			Collection: collection,
			Signature:  signature,
		})
		if err != nil {
			stat, ok := status.FromError(err)
			if !ok || stat.Code() != codes.NotFound {
				ctrl.logger.Error().Err(err).Msgf("cannot get metadata for %s/%s", collection, signature)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("cannot get metadata for %s/%s: %v", collection, signature, err),
				})
				c.Abort()
				return
			}
			ctrl.logger.Error().Err(err).Msgf("%s/%s not found", collection, signature)
			c.JSON(http.StatusNotFound, gin.H{
				"error": fmt.Sprintf("%s/%s not found: %v", collection, signature, err),
			})
			c.Abort()
			return
		}

		c.Data(http.StatusOK, "application/json", []byte(metadata.GetValue()))
		return
	}

	var params = actionCache.ActionParams{}
	if !slices.Contains([]string{"item", "master"}, action) {
		allowedParams, err := ctrl.getParams(item.GetMetadata().GetType(), action)
		if err != nil {
			ctrl.logger.Error().Err(err).Msgf("cannot get params for %s::%s", item.GetMetadata().GetType(), action)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get params for %s::%s: %v", item.GetMetadata().GetType(), action, err),
			})
			return
		}
		params.SetString(paramStr, allowedParams)
	}

	actionID := fmt.Sprintf("%s/%s", action, params.String())
	if tplAny, err := ctrl.actionTemplates.Get(actionID); err == nil {
		tpl, ok := tplAny.(*template.Template)
		if !ok {
			ctrl.logger.Error().Err(err).Msgf("invalid template type %T", tplAny)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("invalid template type %T", tplAny),
			})
			return
		}
		ctrl.doTemplate(c, tpl, collection, signature)
		return
	}

	cache, err := ctrl.dbClient.GetCache(context.Background(), &mediaserverproto.CacheRequest{
		Identifier: &mediaserverproto.ItemIdentifier{
			Collection: collection,
			Signature:  signature,
		},
		Action: action,
		Params: params.String(),
	})
	if err != nil {
		stat, ok := status.FromError(err)
		if !ok || stat.Code() != codes.NotFound {
			ctrl.logger.Error().Err(err).Msgf("cannot get cache for %s/%s/%s", collection, signature, action)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get cache for %s/%s/%s: %v", collection, signature, action, err),
			})
			return
		}
		collAny, err := ctrl.collectionCache.Get(collection)
		if err != nil {
			ctrl.logger.Error().Err(err).Msgf("cannot get collection %s", collection)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get collection %s: %v", collection, err),
			})
			return
		}
		coll, ok := collAny.(*mediaserverproto.Collection)

		// cache not found, create it
		cache, err = ctrl.actionControllerClient.Action(context.Background(), &mediaserverproto.ActionParam{
			Item:    item,
			Action:  action,
			Params:  params,
			Storage: coll.GetStorage(),
		})
		if err != nil {
			ctrl.logger.Error().Err(err).Msgf("cannot get cache for %s/%s/%s: %v", collection, signature, action, err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get cache for %s/%s/%s: %v", collection, signature, action, err),
			})
			return
		}
		if cache == nil {
			ctrl.logger.Error().Msgf("cannot get cache for %s/%s/%s: no cache", collection, signature, action)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot get cache for %s/%s/%s: no cache", collection, signature, action),
			})
			return
		}
	}
	metadata := cache.GetMetadata()
	path := metadata.GetPath()
	matches := dataRegexp.FindStringSubmatch(path)
	if matches != nil {
		if metadata.GetMimeType() == "text/html" && matches[1] == "text/gohtml" {
			tpl, err := template.New(actionID).Parse(strings.TrimPrefix(path, "data:text/gohtml,"))
			if err != nil {
				ctrl.logger.Error().Err(err).Msgf("cannot parse template %s", path)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("cannot parse template %s: %v", path, err),
				})
				return
			}
			ctrl.actionTemplates.Set(actionID, tpl)
			ctrl.doTemplate(c, tpl, collection, signature)
			return
		} else {
			c.Header("Content-Type", metadata.GetMimeType())
			if _, err := io.WriteString(c.Writer, matches[2]); err != nil {
				ctrl.logger.Error().Err(err).Msgf("cannot write data %s", matches[2])
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("cannot write data %s: %v", matches[2], err),
				})
				return
			}
			return
		}
	}
	if !isUrlRegexp.MatchString(path) {
		stor := metadata.GetStorage()
		if stor == nil {
			ctrl.logger.Error().Msgf("no storage defined for %s/%s/%s/%s", collection, signature, action, params.String())
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("no storage defined for %s/%s/%s/%s", collection, signature, action, params.String()),
			})
			return
		}
		path = stor.GetFilebase() + "/" + path
	}

	mime := metadata.GetMimeType()
	switch mime {
	case "text/gohtml":
		data, err := fs.ReadFile(ctrl.vfs, path)
		if err != nil {
			ctrl.logger.Error().Err(err).Msgf("cannot read file %v/%s", ctrl.vfs, path)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot read file %v/%s: %v", ctrl.vfs, path, err),
			})
			c.Abort()
			return
		}
		tpl, err := template.New("action").Parse(string(data))
		if err != nil {
			ctrl.logger.Error().Err(err).Msgf("cannot parse template %v/%s", ctrl.vfs, path)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot parse template %v/%s: %v", ctrl.vfs, path, err),
			})
			return
		}
		c.Header("Content-Type", "text/html")
		if err := tpl.Execute(c.Writer, map[string]string{"BaseURL": ctrl.extAddr}); err != nil {
			ctrl.logger.Error().Err(err).Msgf("cannot execute template %v/%s", ctrl.vfs, path)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("cannot execute template %v/%s: %v", ctrl.vfs, path, err),
			})
			return
		}
	default:
		c.Header("Content-Type", mime)
		c.FileFromFS(path, http.FS(ctrl.vfs))
	}
	return
}
