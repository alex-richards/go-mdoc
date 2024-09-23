module github.com/alex-richards/go-mdoc

go 1.22.6

require (
	github.com/alex-richards/tiny-cbor v1.2.3
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/veraison/go-cose v1.2.1
	golang.org/x/crypto v0.26.0
)

require (
	github.com/x448/float16 v0.8.4 // indirect
)

require (
    github.com/google/go-cmp v0.6.0 // test
)

replace (
    github.com/alex-richards/tiny-cbor => ../tiny-cbor/
)

replace (
    github.com/veraison/go-cose => github.com/alex-richards/go-cose v0.0.0-20240816071327-fa0344c81cf0
)
