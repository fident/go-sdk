# GoFident
Fident client library for validation of GRPC traffic through portcullis.

#### Init
InitWithPubKeyPath(pubKeyPath)
```go
err := gofident.InitWithPubKeyPath("/path/to/pub.pem")
```

#### Verify
Verify(*httpRequest)
```go
verified := gofident.Verify(req)
```

