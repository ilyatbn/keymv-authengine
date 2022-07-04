package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
	"github.com/golang-jwt/jwt"
	"github.com/ilyatbn/keymv-proto/authengine"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	var usersPasswords = map[string]string{
		"user1": "hashedpassword",
		"user2": "hashedpassword2",
	}
	var userOrgs = map[string]int{
		"user1": 1,
		"user2": 199,
	}
	var userRoles = map[string]string{
		"user1": "Admin",
		"user2": "ReadAllValues",
	}


	//check scylla
	userPassword, ok := usersPasswords[credentials.Username]
	if !ok {
		return "", errors.New("user not found in database")
	} else if userPassword != credentials.Password {
		return "", errors.New("incorrect credentials")
	}
	//check redis
	session, ok := sessions[credentials.Username]
	if ok {
		log.Println("user token already found in cache. reauthenticating.")
	}	

	jwt,key, err := GenerateJWT(credentials.Username)
	if err != nil {
		return "", err
	}
	//get more user data from scylla
	userOrg := userOrgs[credentials.Username]
	userRole := userRoles[credentials.Username]

	session = sessionInfo{key,userOrg,userRole,jwt}
	//store session in redis.for now we'll do it in a map of sessions
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
	//sessions=redis
	logger := log.New(os.Stdout, in.RequestId +" ", log.LstdFlags|log.Lmsgprefix)
	logger.Printf("received token validation request")
	session, ok := sessions[in.Token]
	if !ok {
		logger.Println("user not found in cache")
		return &auth.ValidationDataRes{Valid: "false", ShouldRefresh: true}, nil
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(session.PublicKey)
	if err != nil {
		logger.Println("error parsing publicKey from cache:", err)
		return nil, status.Errorf(codes.Internal,"Error with parsing publicKey")
	}
	//Validation. Mostly not my code.
	tok, err := jwt.Parse(session.token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		logger.Printf("there was an error while parsing jwt")
		return nil, fmt.Errorf("validate: %w", err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		logger.Printf("claims token is invalid")
		return nil, fmt.Errorf("validation: invalid")
	}
	//
	
    var exp time.Time
	expClaim,_ := claims["exp"].(float64)
	exp = time.Unix(int64(expClaim), 0)
	un,_ := claims["Username"].(string)
	userData:= sessions[un]
	
	et := time.Until(exp)
	//client will do this check every 10 minutes and if the response contains ShouldRefresh, it will do another Auth
	if et.Minutes() < 60 {
		logger.Printf("token will expire in %v. sending refresh code", et.Minutes())
		return &auth.ValidationDataRes{Valid: "true",OrgId: int32(userData.orgId) ,Role: userData.role,ShouldRefresh: true}, nil
	}
	return &auth.ValidationDataRes{Valid: "true",OrgId: int32(userData.orgId) ,Role: userData.role}, nil
}