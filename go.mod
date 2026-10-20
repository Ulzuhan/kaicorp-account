module github.com/Ulzuhan/kaicorp-account

// Go 1.27.3 incorpora el parche de crypto/x509 del 19-10-2026. El mínimo,
// la imagen de compilación y CI se mantienen en la misma revisión corregida.
go 1.27.3

require github.com/jackc/pgx/v5 v5.11.0

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
