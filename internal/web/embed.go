// Package web embebe las plantillas, el estático y las plantillas de correo.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"sort"
	"sync"
)

//go:embed static/* templates/* plantillas/*
var EmbeddedFS embed.FS

var (
	versionOnce sync.Once
	version     string
)

// AssetVersion es un hash del estático: la URL cambia cuando cambia el
// contenido, y así el borde puede cachear un año sin servir CSS viejo.
func AssetVersion() string {
	versionOnce.Do(func() {
		var paths []string
		_ = fs.WalkDir(EmbeddedFS, "static", func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				paths = append(paths, p)
			}
			return nil
		})
		sort.Strings(paths)
		h := sha256.New()
		for _, p := range paths {
			b, _ := EmbeddedFS.ReadFile(p)
			h.Write([]byte(p))
			h.Write(b)
		}
		version = hex.EncodeToString(h.Sum(nil))[:12]
	})
	return version
}

// StaticFS sirve el estático. El StripPrefix lo pone quien lo monta: sin él,
// la página renderiza, el healthcheck pasa y nada tiene estilos (LinkUp, 02-09).
func StaticFS() http.Handler {
	sub, err := fs.Sub(EmbeddedFS, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") == AssetVersion() {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		}
		files.ServeHTTP(w, r)
	})
}

// Plantilla devuelve una plantilla de correo de GoTrue tal cual, sin procesar:
// las expresiones {{ .TokenHash }} son de GoTrue, no de esta app.
func Plantilla(nombre string) ([]byte, error) {
	return EmbeddedFS.ReadFile("plantillas/" + nombre)
}
