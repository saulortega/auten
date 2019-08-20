package auten

import (
	"errors"
	"log"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func EncriptarContraseña(c string) (string, error) {
	c = strings.TrimSpace(c)
	if len(c) < 8 {
		return "", errors.New("La contraseña debe tener al menos 8 caracteres")
	} else if len(c) > 50 {
		return "", errors.New("La contraseña no debe tener más de 50 caracteres")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(c), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		return "", errors.New("Ocurrió un error. Intente de nuevo más tarde. [2693]")
	}

	return string(hash), nil
}

func ComprobarContraseña(hash string, con string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(con))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			err = ContraseñaErrónea
		} else {
			log.Println(err)
			err = errors.New("No se pudo verificar la contraseña. Intente nuevamente.")
		}
		return err
	}

	return nil
}
