module github.com/weeros/defectdojo

go 1.24

toolchain go1.24.1

require github.com/caarlos0/env/v11 v11.3.1

require (
	github.com/truemilk/go-defectdojo v0.6.3 // indirect
)

replace github.com/truemilk/go-defectdojo v0.6.3 => ../go-defectdojo
