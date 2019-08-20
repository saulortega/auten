package auten

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"

	_ "github.com/lib/pq"
)

func credencialesDesdeRequest(r *http.Request) (string, string, error) {
	var cor, con string

	cor = strings.TrimSpace(strings.ToLower(r.FormValue("correo")))
	if len(cor) == 0 {
		return cor, con, CorreoNoRecibido
	}

	con = strings.TrimSpace(r.FormValue("contraseña"))
	if len(con) == 0 {
		return cor, con, ContraseñaNoRecibida
	}

	return cor, con, nil
}

func datosSegúnCorreo(BDG *sql.DB, correo string) (string, string, string, error) {
	var llaveUsuario, contraseña string

	err := BDG.QueryRow(`SELECT llave,contraseña FROM usuarios WHERE correo = $1`, correo).Scan(&llaveUsuario, &contraseña)
	if err == sql.ErrNoRows {
		return "", "", "", errors.New("Verifique sus credenciales de acceso. [5038]")
	} else if err != nil {
		log.Println(err)
		return "", "", "", errors.New("Error de autenticación. [2503]")
	}

	if len(llaveUsuario) == 0 || len(contraseña) == 0 {
		return "", "", "", errors.New("Error de autenticación. [1583]")
	}

	return llaveUsuario, correo, contraseña, nil
}

func datosSegúnLlaveUsuario(BDG *sql.DB, llaveUsuario string) (string, string, string, error) {
	var correo, contraseña string

	err := BDG.QueryRow(`SELECT correo,contraseña FROM usuarios WHERE llave = $1`, llaveUsuario).Scan(&correo, &contraseña)
	if err == sql.ErrNoRows {
		return "", "", "", errors.New("Error de autenticación. [3593]")
	} else if err != nil {
		log.Println(err)
		return "", "", "", errors.New("Error de autenticación. [4581]")
	}

	if len(llaveUsuario) == 0 || len(contraseña) == 0 {
		return "", "", "", errors.New("Error de autenticación. [2553]")
	}

	return llaveUsuario, correo, contraseña, nil
}

/*
func obtenerConexiónBD(nombreBaseBD string, llave string) (*sql.DB, error) {
	bd, err := sql.Open("postgres", "host=localhost user=postgres dbname="+nombreBaseBD+"_"+llave+" sslmode=disable password=postgres")
	if err != nil {
		log.Println(err)
		return bd, errors.New("Ocurrió un error. Intente nuevamente. [5202]")
	}

	return bd, nil
}
*/
