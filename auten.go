package auten

import (
	"crypto/rsa"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"
)

// Se requiere una tabla llamada "usuarios" con las columnas "llave", "correo", y "contraseña"

var (
	RSAPublicKey  *rsa.PublicKey
	RSAPrivateKey *rsa.PrivateKey
)

type Datos struct {
	LlaveUsuario string
	//LlaveEntidad string
	Correo string
	Token  string
	//BD     *sql.DB
}

var (
	CorreoNoRecibido     = errors.New("No se recibió la dirección de correo electrónico.")
	ContraseñaNoRecibida = errors.New("No se recibió la contraseña.")
	ContraseñaErrónea    = errors.New("Contraseña errónea.")
)

//func Ingreso(nombreBaseBD string, r *http.Request, BDG *sql.DB, RSAPrivateKey *rsa.PrivateKey, tiempo time.Duration) (*Datos, error) {
func Ingreso(r *http.Request, BDG *sql.DB, tiempo time.Duration) (*Datos, error) {
	var datos = new(Datos)
	var hash string

	if RSAPrivateKey == nil {
		log.Println("Falta el certificado privado para autenticar.")
		return datos, errors.New("Error de autenticación. [5920]")
	}

	cor, con, err := credencialesDesdeRequest(r)
	if err != nil {
		return datos, err
	}

	datos.LlaveUsuario, datos.Correo, hash, err = datosSegúnCorreo(BDG, cor)
	if err != nil {
		return datos, err
	}

	err = ComprobarContraseña(hash, con)
	if err != nil {
		return datos, err
	}

	datos.Token, err = CrearToken(RSAPrivateKey, datos.LlaveUsuario, tiempo)
	if err != nil {
		return datos, err
	}

	// Quizás cambiar esto por comprobación de acceso a cada tala...
	//datos.BD, err = obtenerConexiónBD(nombreBaseBD, datos.LlaveEntidad)
	//if err != nil {
	//return datos, err
	//}

	return datos, nil
}

//func Sesión(nombreBaseBD string, r *http.Request, BD *sql.DB, RSAPublicKey *rsa.PublicKey) (*Datos, error) {
func Sesión(r *http.Request, BD *sql.DB) (*Datos, error) {
	var datos = new(Datos)

	if RSAPublicKey == nil {
		log.Println("Falta la llave pública para autenticar.")
		return datos, errors.New("Error de autenticación. [5921]")
	}

	_, claims, err := ComprobarToken(r, RSAPublicKey)
	if err != nil {
		return datos, err
	}

	datos.LlaveUsuario, datos.Correo, _, err = datosSegúnLlaveUsuario(BD, claims.Iden)
	if err != nil {
		return datos, err
	}

	// Quizás cambiar esto por comprobación de acceso a cada tala...
	//datos.BD, err = obtenerConexiónBD(nombreBaseBD, datos.LlaveEntidad)
	//if err != nil {
	//return datos, err
	//}

	return datos, nil
}
