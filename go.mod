module github.com/weeros/defectdojo

go 1.24

toolchain go1.24.1

require (
	github.com/caarlos0/env/v11 v11.3.1
	github.com/truemilk/go-defectdojo v0.6.2
	github.com/google/go-cmp v0.7.0 // indirect
)

//replace github.com/truemilk/go-defectdojo v0.6.2 => ../go-defectdojo 
