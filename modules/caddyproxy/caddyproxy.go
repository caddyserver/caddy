package caddyproxy

import (
	"net"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	err := caddy.RegisterModule(new(App))
	if err != nil {
		caddy.Log().Fatal(err.Error())
	}
}

func (app *App) Provision(ctx caddy.Context) error {
	app.logger = ctx.Logger(app)
	return nil
}

// CaddyModule implement caddy.Module interface
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "proxy",
		New:  func() caddy.Module { return new(App) },
	}
}

func (app *App) Start() error {
	httpAppIface, err := app.ctx.App("http")
	if err != nil {
		return err
	}
	httpApp := httpAppIface.(*caddyhttp.App)
	app.http = httpApp

	for addr, proxy := range app.router {
		ln, err := net.Listen(proxy.network, addr)
		if err != nil {
			app.logger.Error(err.Error())
			return err
		}

		go app.serveListener(ln, proxy)
	}
	return nil
}

func (app *App) Stop() error {
	return nil
}

type App struct {
	// proxy map address to its proxy
	router map[string]*proxy

	BufferSize int `json:"buffer_size,omitempty"`
	// other configs

	http *caddyhttp.App

	ctx    caddy.Context
	logger *zap.Logger
}

func (app *App) serveListener(ln net.Listener, p *proxy) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			app.logger.Error(err.Error())
			return
		}
		go app.serveConn(conn, p)
	}
}

func goCloseConn(conn net.Conn) {
	go conn.Close()
}

func (app *App) serveConn(src net.Conn, p *proxy) {

	defer goCloseConn(src)
	dst, err := p.to.Dial(app.ctx)
	if err != nil {
		app.logger.Error("proxy dial dest error: " + err.Error())
		return
	}
	defer goCloseConn(dst)
	for _, h := range p.handleChain {
		// TODO: add option to buffer the conn
		err := h.Handle(app.ctx, dst, src)
		if err != nil {
			app.logger.Error("proxy: " + err.Error())
			return
		}
	}

	// proxy to dest
	p.to.Proxy(app.ctx, dst, src)
}

type Proxier interface {
	Proxy(ctx caddy.Context, dst net.Conn, src net.Conn) error
	Dial(ctx caddy.Context) (net.Conn, error)
}

type proxy struct {
	// handleChain is the chain to custom proxy
	// if not provided, data will be proxy to dest automatically
	// listened port -> Handler -> Handler -> destination
	handleChain []Handler

	// to is the Handler to do the real proxy to dest
	to Proxier

	network string
	from    string

	ctx caddy.Context
}

func (p *proxy) Network() string {
	return p.network
}

func (app *App) TCP(from string, to Proxier, h ...HandleFunc) {
	handlers := make([]Handler, 0, len(h))
	for _, handle := range h {
		handlers = append(handlers, handle)
	}
	app.addProxyHandler("tcp", from, to, handlers...)
}

func (app *App) UDP(from string, to Proxier, h ...HandleFunc) {
	handlers := make([]Handler, 0, len(h))
	for _, handle := range h {
		handlers = append(handlers, handle)
	}
	app.addProxyHandler("udp", from, to, handlers...)
}

func (app *App) AddProxy(net, from string, to Proxier) {
	app.addProxyHandler(net, from, to)
}

func (app *App) addProxyHandler(net, from string, to Proxier, h ...Handler) {
	if r, ok := app.router[from]; ok {
		r.handleChain = append(r.handleChain, h...)
		return
	}
	app.router[from] = &proxy{
		handleChain: h,
		network:     net,
		from:        from,
		to:          to,
		ctx:         app.ctx,
	}
}
