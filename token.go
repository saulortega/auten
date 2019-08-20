package auten

import (
	"crypto/rsa"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
)

type Claims struct {
	Iden string `json:"iden"`
	jwt.StandardClaims
}

func CrearToken(RSAPrivateKey *rsa.PrivateKey, llave string, tiempo time.Duration) (string, error) {
	var claims = Claims{}
	claims.Iden = llave
	claims.ExpiresAt = time.Now().Add(tiempo).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tkn, err := token.SignedString(RSAPrivateKey)
	if err != nil {
		log.Println(err)
		return "", errors.New("No se pudo generar el token. Intente nuevamente.")
	}

	return tkn, nil
}

func ComprobarToken(r *http.Request, RSAPublicKey *rsa.PublicKey) (*jwt.Token, *Claims, error) {
	var claims = new(Claims)
	var Err error

	var token, err = request.ParseFromRequest(r, request.OAuth2Extractor, func(tkn *jwt.Token) (interface{}, error) { return RSAPublicKey, nil }, request.WithClaims(claims))
	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			vErr := err.(*jwt.ValidationError)
			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				Err = errors.New("Su sesión expiró.")
			default:
				log.Println(err)
				Err = errors.New("Sesión no válida. [5922]")
			}
		default:
			log.Println(err)
			Err = errors.New("Sesión no válida. [9063]")
		}

		return token, claims, Err
	}

	if !token.Valid {
		return token, claims, errors.New("Sesión no válida. [5591]")
	}

	if len(claims.Iden) == 0 {
		return token, claims, errors.New("Token no válido [4283]")
	}

	return token, claims, nil
}
