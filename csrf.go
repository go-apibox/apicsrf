package apicsrf

import (
	"net/http"
	"strings"

	"github.com/go-apibox/api"
	"github.com/go-apibox/session"
	"github.com/go-apibox/utils"
)

type CSRF struct {
	app      *api.App
	disabled bool
	inited   bool

	store         *session.CookieStore
	httpHeader    string
	sessionName   string
	sessionKey    string
	actionMatcher *utils.Matcher
}

func NewCSRF(app *api.App) *CSRF {
	app.Error.RegisterGroupErrors("csrf", ErrorDefines)

	csrf := new(CSRF)
	csrf.app = app

	cfg := app.Config
	disabled := cfg.GetDefaultBool("apicsrf.disabled", false)
	csrf.disabled = disabled
	if disabled {
		return csrf
	}

	csrf.init()
	return csrf
}

func (cs *CSRF) init() {
	if cs.inited {
		return
	}

	app := cs.app
	cfg := app.Config
	httpHeader := cfg.GetDefaultString("apicsrf.http_header", "X-CSRF-TOKEN")
	storeKey := cfg.GetDefaultString("apicsrf.session_store_key", "default.csrf_token")
	actionWhitelist := cfg.GetDefaultStringArray("apicsrf.actions.whitelist", []string{"*"})
	actionBlacklist := cfg.GetDefaultStringArray("apicsrf.actions.blacklist", []string{})

	parts := strings.SplitN(storeKey, ".", 2)
	if len(parts) != 2 {
		parts = []string{"default", "csrf_token"}
	}
	sessionName := parts[0]
	sessionKey := parts[1]

	matcher := utils.NewMatcher()
	matcher.SetWhiteList(actionWhitelist)
	matcher.SetBlackList(actionBlacklist)

	store, err := app.SessionStore()
	if err != nil {
		cs.app.Logger.Error("(apicsrf) cookie store init failed, csrf not disabled: %s", err.Error())
	}

	cs.store = store
	cs.httpHeader = httpHeader
	cs.sessionName = sessionName
	cs.sessionKey = sessionKey
	cs.actionMatcher = matcher
	cs.inited = true
}

func (cs *CSRF) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if cs.disabled {
		next(w, r)
		return
	}

	c, err := api.NewContext(cs.app, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// check if csrf is enable
	if cs.sessionName == "" {
		next(w, r)
		return
	}

	// check if action not required csrf check
	action := c.Input.GetAction()
	if !cs.actionMatcher.Match(action) {
		next(w, r)
		return
	}

	// check session
	if cs.store == nil {
		api.WriteResponse(c, c.Error.NewGroupError("csrf", errorSessionInitFailed))
		return
	}
	session, err := cs.store.Get(r, cs.sessionName)
	if err != nil {
		api.WriteResponse(c, c.Error.NewGroupError("csrf", errorSessionGetFailed))
		return
	}
	token, ok := session.Values[cs.sessionKey]
	if !ok {
		api.WriteResponse(c, c.Error.NewGroupError("csrf", errorCSRFTokenError))
		return
	}
	csrfToken, ok := token.(string)
	if !ok {
		api.WriteResponse(c, c.Error.NewGroupError("csrf", errorCSRFTokenError))
		return
	}

	// 获取请求中的CSRF TOKEN
	// 优先级：头部=>GET/POST
	reqCsrfToken := r.Header.Get(cs.httpHeader)
	if reqCsrfToken == "" {
		reqCsrfToken = c.Input.Get("api_csrf_token")
	}
	if reqCsrfToken != csrfToken {
		api.WriteResponse(c, c.Error.NewGroupError("csrf", errorCSRFTokenError))
		return
	}

	// next middleware
	next(w, r)
}

// Enable enable the middle ware.
func (cs *CSRF) Enable() {
	cs.disabled = false
	cs.init()
}

// Disable disable the middle ware.
func (cs *CSRF) Disable() {
	cs.disabled = true
}
