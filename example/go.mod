module main

go 1.20

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/salrashid123/golang-jwt-yubikey v1.0.0
)

require github.com/go-piv/piv-go v1.11.0 // indirect

replace github.com/salrashid123/golang-jwt-yubikey => ../
