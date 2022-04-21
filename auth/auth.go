package auth

import (
	"log"
	"os"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"github.com/ilyatbn/keymv-proto/authengine"
)

type Server struct {
	auth.UnimplementedAuthEngineServer
}

func AuthUser(token string) bool {
	//check in redis if this token already exists, return the details
	//if not, request the orm microservice to check.
	
	//this is just for the skeleton build
	return token == "12345678a"

}

func (s *Server) Auth(ctx context.Context, in *auth.Request) (*auth.Response, error) {
	logger := log.New(os.Stdout, in.RequestId +" ", log.LstdFlags|log.Lmsgprefix)
	logger.Println("Received auth check:"+in.AuthToken)
	ok := AuthUser(in.AuthToken)
	if !ok {
		msg := "Authentication Error. Not found in db."
		logger.Println(msg)
		return nil, status.Errorf(codes.Unauthenticated, msg)
	}
	return &auth.Response{Orgid: "1"}, nil
}