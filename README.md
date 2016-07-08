# GoFident
Fident client library for Go

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

