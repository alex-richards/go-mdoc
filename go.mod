module github.com/alex-richards/go-mdoc

go 1.23.0

toolchain go1.23.5

require (
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/jawher/mow.cli v1.2.0
	github.com/veraison/go-cose v1.3.0
	golang.org/x/crypto v0.36.0
)

require github.com/x448/float16 v0.8.4 // indirect

require github.com/google/go-cmp v0.7.0 // test

//replace (
//    github.com/alex-richards/tiny-cbor => ../tiny-cbor/
//)
//
//replace (
//    github.com/veraison/go-cose => github.com/alex-richards/go-cose v0.0.0-20240816071327-fa0344c81cf0
//)
