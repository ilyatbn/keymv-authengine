package auth

import (
	"log"
	"os"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	UnimplementedParamReaderServer
}


func (s *Server) GetParam(ctx context.Context, in *Request) (*Response, error) {
	logger := log.New(os.Stdout, in.RequestId +" ", log.LstdFlags|log.Lmsgprefix)
	logger.Println("Received auth check:"+in.AuthToken)
	ok := true
	if !ok {
		msg := "Authentication Error. Ref:"+logger.Prefix()
		logger.Println(msg)
		return nil, status.Errorf(codes.Unauthenticated, msg)
	}
	return &Response{Orgid: "1"}, nil
}