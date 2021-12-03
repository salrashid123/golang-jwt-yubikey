module main

go 1.17

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/salrashid123/golang-jwt-yubikey v0.0.0
)

require github.com/go-piv/piv-go v1.9.0 // indirect

replace github.com/salrashid123/golang-jwt-yubikey => ../
