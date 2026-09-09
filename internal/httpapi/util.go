package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/Ulzuhan/kaicorp-account/internal/web"
)

func webPlantilla(nombre string) ([]byte, error) { return web.Plantilla(nombre) }

func contextoBreve(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 5*time.Second)
}
