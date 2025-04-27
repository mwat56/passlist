module github.com/mwat56/passlist

go 1.23.0

toolchain go1.23.5

require (
	github.com/mwat56/sourceerror v0.3.0
	golang.org/x/crypto v0.37.0
	golang.org/x/term v0.31.0
)

require golang.org/x/sys v0.32.0 // indirect

replace (
	github.com/mwat56/passlist => ../passlist
	github.com/mwat56/sourceerror => ../sourceerror
)
