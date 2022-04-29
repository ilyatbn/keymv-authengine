module github.com/ilyatbn/keymv-authengine

go 1.18

require (
	github.com/lithammer/shortuuid/v4 v4.0.0
	golang.org/x/net v0.0.0-20200822124328-c89045814202
	google.golang.org/grpc v1.45.0
	google.golang.org/protobuf v1.26.0
)

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/ilyatbn/keymv-proto v0.0.0-20220421093344-551e433bd7af // indirect
	golang.org/x/sys v0.0.0-20200323222414-85ca7c5b95cd // indirect
	golang.org/x/text v0.3.0 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
)

replace github.com/ilyatbn/keymv-proto v0.0.0-20220421093344-551e433bd7af => ../keymv-proto
