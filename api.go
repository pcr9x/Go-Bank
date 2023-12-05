package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

type APIServer struct {
	listenAddr string
	store      Storage
}

const (
    endpointLogin    = "/login"
    endpointAccount  = "/account"
    endpointTransfer = "/transfer"
	endpointDeposit  = "/deposit"
	endpointWithdraw = "/withdraw"

	httpMethodGet    = "GET"
	httpMethodPost   = "POST"
	httpMethodDelete = "DELETE"
)

func NewAPIServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (server *APIServer) Run() {
	router := mux.NewRouter()

	router.Use(loggingMiddleware)

	router.HandleFunc(endpointLogin, makeHTTPHandler(server.handleLogin))
	router.HandleFunc(endpointAccount, makeHTTPHandler(server.handleAccount))
	router.HandleFunc(endpointAccount + "/{id}", withJWTAuth(makeHTTPHandler(server.handleGetAccountByID), server.store))
	router.HandleFunc(endpointTransfer, makeHTTPHandler(server.handleTransfer))
	router.HandleFunc(endpointDeposit, makeHTTPHandler(server.handleDeposit))
	router.HandleFunc(endpointWithdraw, makeHTTPHandler(server.handleWithdraw))

	log.Println("Starting API server on", server.listenAddr)

	http.ListenAndServe(server.listenAddr, router)
}

func loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("Request: %s %s", r.Method, r.URL.Path)

        next.ServeHTTP(w, r)
    })
}

func (server *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != httpMethodPost {
		return fmt.Errorf("method not allowed %s", r.Method)
	}
	
	loginReq := new(LoginRequest)
	if err := json.NewDecoder(r.Body).Decode(loginReq); err != nil {
		return err
	}

	account, err := server.store.GetAccountByNumber(loginReq.Number)
	if err != nil {	
		return err
	}

	if err := account.ComparePassword(loginReq.Password); err != nil {
		return fmt.Errorf("not authenticated")
	}

	token, err := createJWT(account)
	if err != nil {
		return err
	}

	res := &LoginResponse{
		Number: account.Number,
		Token:  token,
	}

	return WriteJSON(w, http.StatusOK, res)
}

func (server *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == httpMethodGet {
		return server.handleGetAccount(w, r)
	} else if r.Method == httpMethodPost {
		return server.handleCreateAccount(w, r)
	}

	return fmt.Errorf("method not allowed %s", r.Method)
}

func (server *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error {
	accounts, err := server.store.GetAccounts()
	if err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, accounts)
}

func (server *APIServer) handleGetAccountByID(w http.ResponseWriter, r *http.Request) error {
	if r.Method == httpMethodGet {
		id, err := getID(r)
		if err != nil {
			return err
		}

		account, err := server.store.GetAccountByID(id)
		if err != nil {
			return err
		}

		return WriteJSON(w, http.StatusOK, account)
	} else if r.Method == httpMethodDelete {
		return server.handleDeleteAccount(w, r)
	}

	return fmt.Errorf("method not allowed %s", r.Method)
}

func (server *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	req := new(CreateAccountRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return err
	}

	defer r.Body.Close()

	account, err := NewAccount(req.FirstName, req.LastName, req.Password)
	if err != nil {
		return err
	}

	if err := server.store.CreateAccount(account); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, account)
}

func (server *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id, err := getID(r)
	if err != nil {
		return err
	}

	if err := server.store.DeleteAccount(id); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

func (server *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
    transferReq := new(TransferRequest)
    if err := json.NewDecoder(r.Body).Decode(transferReq); err != nil {
        return err
    }

    defer r.Body.Close()

    authorizationHeader := r.Header.Get("Authorization")
    customClaims, err := validateJWT(authorizationHeader)
    if err != nil || customClaims == nil {
        return err
    }

    if err := customClaims.Valid(); err != nil {
        return err
    }

    if transferReq.FromAccount != customClaims.AccountNumber {
        permissionDenied(w)
        return fmt.Errorf("permission denied")
    }

    fromAccount, err := server.store.GetAccountByNumber(customClaims.AccountNumber)
    if err != nil {
        return err
    }

    toAccount, err := server.store.GetAccountByNumber(transferReq.ToAccount)
    if err != nil {
        return err
    }

	if err := server.processTransfer(fromAccount, toAccount, transferReq); err != nil {
		return err
	}

    return WriteJSON(w, http.StatusOK, TransactionResponse{Message: "transfer successful", UpdatedBalance: fromAccount.Balance})
}

func (server *APIServer) handleTransaction(w http.ResponseWriter, r *http.Request, processTransaction func(*Account, *Account, float64) error) error {
    transactionReq := new(TransactionRequest)
    if err := json.NewDecoder(r.Body).Decode(transactionReq); err != nil {
        return err
    }

    defer r.Body.Close()

    authorizationHeader := r.Header.Get("Authorization")
    customClaims, err := validateJWT(authorizationHeader)
    if err != nil || customClaims == nil {
        return err
    }

    if err := customClaims.Valid(); err != nil {
        return err
    }

    account, err := server.store.GetAccountByNumber(customClaims.AccountNumber)
    if err != nil {
        return err
    }

    if transactionReq.Number != customClaims.AccountNumber {
        permissionDenied(w)
        return fmt.Errorf("permission denied")
    }

    if err := processTransaction(account, nil, transactionReq.Amount); err != nil {
        return err
    }

    return WriteJSON(w, http.StatusOK, TransactionResponse{Message: "transaction successful", UpdatedBalance: account.Balance})
}

func (server *APIServer) handleDeposit(w http.ResponseWriter, r *http.Request) error {
    if r.Method != httpMethodPost {
        return fmt.Errorf("method not allowed %s", r.Method)
    }
    return server.handleTransaction(w, r, server.processDeposit)
}

func (server *APIServer) handleWithdraw(w http.ResponseWriter, r *http.Request) error {
    if r.Method != httpMethodPost {
        return fmt.Errorf("method not allowed %s", r.Method)
    }
    return server.handleTransaction(w, r, server.processWithdraw)
}

func (server *APIServer) processTransfer(fromAccount, toAccount *Account, transactionReq *TransferRequest) error {
    if fromAccount.Balance < transactionReq.Amount {
        return fmt.Errorf("insufficient funds")
    }

    fromAccount.Balance -= transactionReq.Amount
    toAccount.Balance += transactionReq.Amount

    if err := server.store.UpdateAccountBalance(fromAccount.Number, fromAccount.Balance); err != nil {
        return err
    }
    if err := server.store.UpdateAccountBalance(toAccount.Number, toAccount.Balance); err != nil {
        return err
    }

    return nil
}

func (server *APIServer) processDeposit(account *Account, _ *Account, amount float64) error {
    account.Balance += amount

    if err := server.store.UpdateAccountBalance(account.Number, account.Balance); err != nil {
        return err
    }

    return nil
}

func (server *APIServer) processWithdraw(account *Account, _ *Account, amount float64) error {
    if account.Balance < amount {
        return fmt.Errorf("insufficient funds")
    }

    account.Balance -= amount

    if err := server.store.UpdateAccountBalance(account.Number, account.Balance); err != nil {
        return err
    }

    return nil
}

type CustomClaims struct {
	ExpiredAt     int64 `json:"expiredAt"`
	AccountNumber int64 `json:"accountNumber"`
	jwt.StandardClaims
}

func (c *CustomClaims) Valid() error {
    now := time.Now().Unix()
    if c.ExpiredAt < now {
        return jwt.NewValidationError("token is expired", jwt.ValidationErrorExpired)
    }

    return nil
}


func createJWT(account *Account) (string, error) {
	customClaims := &CustomClaims{
		ExpiredAt:     time.Now().Add(time.Hour).Unix(), // Set expiration time as an example (1 hour from now)
		AccountNumber: account.Number,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims)

	secret := os.Getenv("JWT_SECRET")
	return token.SignedString([]byte(secret))
}


func permissionDenied(w http.ResponseWriter) {
	WriteJSON(w, http.StatusUnauthorized, ApiError{Error: "permission denied"})
}

func withJWTAuth(handlerFunc http.HandlerFunc, s Storage) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authorizationHeader := r.Header.Get("Authorization")

        token, err := validateJWT(authorizationHeader)
        if err != nil {
            permissionDenied(w)
            return
        }

        if err := token.Valid(); err != nil {
            permissionDenied(w)
            return
        }

        userID, err := getID(r)
        if err != nil {
            permissionDenied(w)
            return
        }

        account, err := s.GetAccountByID(userID)
        if err != nil {
            permissionDenied(w)
            return
        }

        if account.Number != token.AccountNumber {
            permissionDenied(w)
            return
        }

        handlerFunc(w, r)
    }
}


func validateJWT(authorizationHeader string) (*CustomClaims, error) {
	secret := os.Getenv("JWT_SECRET")

	token, err := jwt.ParseWithClaims(authorizationHeader, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method %s", token.Header["alg"])
		}

		return []byte(secret), nil
	})

	if err != nil {
		log.Println("Error parsing token:", err)
		return nil, err
	}

	customClaims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		log.Println("Invalid token:", token)
		return nil, fmt.Errorf("invalid token")
	}

	return customClaims, nil
}



type apiFunc func(http.ResponseWriter, *http.Request) error

type ApiError struct {
	Error string `json:"error"`
}

type TransactionResponse struct {
    Message      string  `json:"message"`
    UpdatedBalance float64 `json:"updatedBalance"`
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)

	return json.NewEncoder(w).Encode(v)
}

func makeHTTPHandler(apiHandler apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := apiHandler(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

func getID(r *http.Request) (int, error) {
	idString := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idString)
	if err != nil {
		return 0, fmt.Errorf("invalid id given %s", idString)
	}

	return id, nil
}
