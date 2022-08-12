package grpc_client

import (
	"fmt"
	"log"
	"os"
	db "github.com/ilyatbn/keymv-proto/dbengine"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func GetUserData(server string, email string, refId string) (*db.UserLogonData, error){
	//figure out a way to use a global logger instead of creating new ones each time
	logger := log.New(os.Stdout, refId+" ", log.LstdFlags|log.Lmsgprefix)
	var conn *grpc.ClientConn
	conn, err := grpc.Dial(server, grpc.WithInsecure())
	if err != nil {
		logger.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()
	c := db.NewDBEngineClient(conn)
	response, err := c.GetUserLogonData(context.Background(), &db.EmailReq{Email: email})
	if err != nil {
		logger.Printf("Error requesting userdata:%s", err)
		return nil, fmt.Errorf("error while requesting userdata:%v", err)
	}
	
	return response, nil
}
