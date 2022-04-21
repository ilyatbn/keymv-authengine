package main

import (
	"log"
	"net"
	"google.golang.org/grpc"
	"github.com/ilyatbn/keymv-authengine/auth"
	authengine "github.com/ilyatbn/keymv-proto/authengine"
)

func main() {
	listenPort := ":49001"
	lis, err := net.Listen("tcp4", listenPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	paramServer := auth.Server{}
	grpcServer := grpc.NewServer()
	authengine.RegisterAuthEngineServer(grpcServer, &paramServer)
	log.Printf("authEngine Listening on 0.0.0.0"+listenPort)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}
}