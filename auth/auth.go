package auth

import (
	"errors"
	"log"
	"os"
	"fmt"
	"time"
	"crypto/rand"
	"crypto/rsa"
	"github.com/golang-jwt/jwt"
	"github.com/ilyatbn/keymv-proto/authengine"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"crypto/x509"
	"encoding/pem"
)
type Server struct {
	auth.UnimplementedAuthEngineServer
}
type Credentials struct {
	Password string
	Username string
}

type sessionInfo struct {
	PublicKey []byte
	orgId int
	role string
	token string

}

type Claims struct {
	Username string
	jwt.StandardClaims
}


var jwtExpirationMin time.Duration = 1440
var rsaKeySize = 1024

var sessions = map[string]sessionInfo{}

func newRSAKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		log.Fatalf("Failed to generate a pair of keys %v", err)
		return nil,err
	}
	return privateKey, nil
}


func GenerateJWT(username string) (string, []byte, error) {
	expirationTime := time.Now().Add(jwtExpirationMin * time.Minute)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	//Switch to ed25519 later
	pvk, err := newRSAKey()
	if err != nil {
		log.Printf("error in rsa key generation:%v",err)
		return "", nil, errors.New("error generating JWT key")
	}
	tokenString, err := token.SignedString(pvk)
	if err != nil {
		log.Printf("error in signedstring:%v",err)
		return "", nil, errors.New("error generating JWT key")
	}
	pk, err := x509.MarshalPKIXPublicKey(&pvk.PublicKey)
	if err != nil {
		log.Printf("error converting publiKey:%v",err)
		return "", nil, errors.New("error generating JWT key")
	}	
	encodedPk := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pk,
	})
	return tokenString, encodedPk, nil
}

func AuthUser(credentials Credentials) (string, error) {
	//scylla representation. temp.
	var users = map[string]string{
		"user1": "hashedpassword",
		"user2": "hashedpassword2",
	}
	//check redis
	session, ok := sessions[credentials.Username]
	if ok {
		log.Println("user found in cache.")
		return session.token,nil
	}	
	
	userPassword, ok := users[credentials.Username]
	//check in redis if this token already exists, return the details
	//if not, request the db microservice.
	
	if !ok {
		return "", errors.New("user not found in database")
	} else if userPassword != credentials.Password {
		return "", errors.New("incorrect password")
	}
	jwt,key, err := GenerateJWT(credentials.Username)
	if err != nil {
		return "", err
	}
	session = sessionInfo{key,1,"Admin",jwt}
	//store session in reddis.for now we'll do it in a map of sessions
	//figure out a way to less this make crappy so that we dont have to store every session twice. it's dumb.
	sessions[jwt] = session
	sessions[credentials.Username] = session

	return jwt, nil
}

func (s *Server) Auth(ctx context.Context, in *auth.Credentials) (*auth.ResponseToken, error) {
	logger := log.New(os.Stdout, in.RequestId +" ", log.LstdFlags|log.Lmsgprefix)
	logger.Println("Received auth check:"+in.Username)
	
	creds := Credentials{
		Username: in.Username,
		Password: in.Password,
	}
	jwt, err := AuthUser(creds)
	
	if err!=nil{
		logger.Println(err)
		return nil, status.Errorf(codes.Unauthenticated, "AUTH_ERR",err)
	}
	return &auth.ResponseToken{Token: jwt}, nil
}



func (s *Server) Validate(ctx context.Context, in *auth.ValidationDataReq) (*auth.ValidationDataRes, error) {
	//decode jwt. get info from redis. if something there, respond with data, if not, assume authentication expired/unauthenticated.
	logger := log.New(os.Stdout, "AuthEngine" +" ", log.LstdFlags|log.Lmsgprefix)
	//do a special validation that this is coming from inside the system or make this only available internally somehow. THIS IS CRITICAL
	//TWO SERVERS?
	session, ok := sessions[in.Userinfo]
	if !ok {
		logger.Println("user not found in cache")
		return &auth.ValidationDataRes{Valid: "false"}, nil
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(session.PublicKey)
	if err != nil {
		logger.Println("error parsing publicKey from cache:", err)
		return nil, status.Errorf(codes.Internal,"Error with parsing publicKey")
	}

	//i dont like this shit since its not my code. do something to checkthat the JWT is Valid
	tok, err := jwt.Parse(session.token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("validate: invalid")
	}
	_ = claims
	///////////////////////////////////////////////////////////////////////////////
	return &auth.ValidationDataRes{Valid: "true",OrgId: "1",Role: "Admin"}, nil
}