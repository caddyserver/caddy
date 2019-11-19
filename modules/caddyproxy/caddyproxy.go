package caddyproxy

import (
	"bufio"
	"bytes"
	"net"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyproxy/tcp"
	"github.com/caddyserver/caddy/v2/modules/caddyproxy/udp"
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

func (app *App) serveConn(conn net.Conn, p *proxy) {

	defer conn.Close()
	data := bytes.NewBuffer(make([]byte, app.BufferSize))
	w := bufio.NewWriter(data)
	for _, h := range p.handleChain {
		err := h.Handle(app.ctx, conn, w)
		if err != nil {
			app.logger.Error("proxy: " + err.Error())
			return
		}
	}

	// proxy to dest
	p.proxier.Proxy(app.ctx, conn, bufio.NewReader(data))
}

type proxier interface {
	Proxy(ctx caddy.Context, conn net.Conn, buf *bufio.Reader)
}
type proxy struct {
	// handleChain is the chain to custom proxy
	// if not provided, data will be proxy to dest automatically
	// listened port -> Handler -> Handler -> destination
	handleChain []Handler

	// proxier is the Handler to do the real proxy to dest
	proxier proxier

	network  string
	from, to string

	ctx caddy.Context
}

func (p *proxy) Network() string {
	return p.network
}

func (app *App) TCP(from, to string, h ...HandleFunc) {
	handlers := make([]Handler, 0, len(h))
	for _, handle := range h {
		handlers = append(handlers, handle)
	}
	app.addProxyHandler("tcp", from, to, handlers...)
}

func (app *App) UDP(from, to string, h ...HandleFunc) {
	handlers := make([]Handler, 0, len(h))
	for _, handle := range h {
		handlers = append(handlers, handle)
	}
	app.addProxyHandler("udp", from, to, handlers...)
}

func (app *App) AddProxy(net, from, to string) {
	app.addProxyHandler(net, from, to)
}

func (app *App) addProxyHandler(net, from, to string, h ...Handler) {
	if r, ok := app.router[from]; ok {
		r.handleChain = append(r.handleChain, h...)
		return
	}
	var proxier proxier
	switch net {
	case "tcp":
		proxier = new(tcp.Proxy)
	case "udp":
		proxier = new(udp.Proxy)
	}
	app.router[from] = &proxy{
		handleChain: h,
		proxier:     proxier,
		network:     net,
		from:        from,
		to:          to,
		ctx:         app.ctx,
	}
}
