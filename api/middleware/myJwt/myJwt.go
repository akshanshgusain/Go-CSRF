package myJwt

import (
	"crypto/rsa"
	"github.com/akshanshgusain/Go-CSRF/db"
	"github.com/akshanshgusain/Go-CSRF/db/models"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"time"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath  = "keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func InitJWT() error {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	return nil
}

func CreateNewTokens(
	uuid string,
	role string,
) (authTokenString, refreshTokenString, csrfSecret string, err error) {

	// generate the csrf secret
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}
	//generating the refresh token
	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)

	// generating the auth token
	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	return
}

func CheckAndRefreshTokens(
	oldAuthTokenString string,
	oldRefreshTokenString string,
	oldCsrfSecret string,
) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {

}

// Creates the Auth Token

func createAuthTokenString(
	uuid string,
	role string,
	csrfSecret string,
) (authTokenString string, err error) {

	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExp,
		},
		Role: role,
		Csrf: csrfSecret,
	}

	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)

	authTokenString, err = authJwt.SignedString(signKey)
	return
}

// Creates the Refresh Token

func createRefreshTokenString(
	uuid string,
	role string,
	csrfString string,
) (refreshTokenString string, err error) {

	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}

	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        refreshJti,
			Subject:   uuid,
			ExpiresAt: refreshTokenExp,
		},
		role,
		csrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func updateRefreshTokenExp(
	oldRefreshTokenString string,
) (newRefreshTokenString string, err error) {

}

func updateAuthTokenString(
	refreshTokenString string,
	oldAuthTokenString string,
) (newAuthTokenString, csrfSecret string, err error) {

}

func RevokeRefreshToken(refreshTokenString string) error {}

func updateRefreshTokenCsrf(
	oldRefreshTokenString string,
	newCsrfString string,
) (newRefreshTokenString string, err error) {
}

func GrabUUID(authTokenString string) (string, error) {

}
