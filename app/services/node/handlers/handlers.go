package handlers

import (
	"context"
	"net/http"
	"os"

	v1 "github.com/startdusk/blockchain/app/services/node/handlers/v1"
	"github.com/startdusk/blockchain/business/web/v1/mid"
	"github.com/startdusk/blockchain/foundation/web"
	"go.uber.org/zap"
)

// MuxConfig contains all the mandatory systems required by handlers.
type MuxConfig struct {
	Shutdown chan os.Signal
	Log      *zap.SugaredLogger
}

// PublicMux constructs a http.Handler with all application routes defined.
func PublicMux(cfg MuxConfig) http.Handler {

	// Construct the web.App which holds all routes as well as common Middleware.
	app := web.NewApp(
		cfg.Shutdown,
		mid.Logger(cfg.Log),
		mid.Errors(cfg.Log),
		mid.Cors("*"),
		mid.Panics(),
	)

	// Accept CORS 'OPTIONS' preflight requests if config has been provided.
	// Don't forget to apply the CORS middleware to the routes that need it.
	// Example Config: `conf:"default:https://MY_DOMAIN.COM"`
	h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		return nil
	}
	app.Handle(http.MethodOptions, "", "/*", h, mid.Cors("*"))

	// Load the v1 routes.
	v1.PublicRoutes(app, v1.Config{
		Log: cfg.Log,
	})

	return app
}
