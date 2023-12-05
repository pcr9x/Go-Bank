package main

import (
	"math/rand"
	"time"
	"golang.org/x/crypto/bcrypt"
)

type LoginResponse struct {
	Number int64 `json:"number"`
	Token string `json:"token"`
}

type LoginRequest struct {
	Number int64  `json:"number"`
	Password string `json:"password"`
}

type TransactionRequest struct {
	Number int64   `json:"number"`
	Amount float64 `json:"amount"`
}

type TransferRequest struct {
	FromAccount int64 `json:"fromAccount"`
	ToAccount int64 `json:"toAccount"`
	Amount    float64 `json:"amount"`
}

type CreateAccountRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Password  string `json:"password"`
}

type Account struct {
	ID        int       `json:"id"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
	Number    int64     `json:"number"`
	EncryptedPassword string `json:"-"`
	Balance   float64   `json:"balance"`
	CreatedAt time.Time `json:"createdAt"`
}

func (a *Account) ComparePassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(a.EncryptedPassword), []byte(password))
}

func NewAccount(firstname, lastname, password string) (*Account, error) {
	encpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	number := rand.Intn(900000) + 100000

	return &Account{
		FirstName: firstname,
		LastName:  lastname,
		Number:    int64(number),
		EncryptedPassword: string(encpw),
		CreatedAt: time.Now().UTC(),
	}, nil
}
