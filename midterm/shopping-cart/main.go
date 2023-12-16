package main

import (
    "database/sql"
    "encoding/json"
    "github.com/gorilla/mux"
    "github.com/google/uuid"
    "log"
    "net/http"
    "time"
    "strings"
    "context"
    "fmt"
    "golang.org/x/crypto/bcrypt"
    _ "github.com/mattn/go-sqlite3"
    "github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("55148077639222633908742447138644")
type contextKey string

const userIDKey contextKey = "userID"

type Claims struct {
    UserID string `json:"user_id"`
    Username string `json:"username"` 
    jwt.StandardClaims
}

func main() {
    db, err := initDB()
    if err != nil {
        log.Fatal("Error initializing database: ", err)
    }
    defer db.Close()

    handler := &AppHandler{DB: db}

    router := mux.NewRouter()

    router.Handle("/basket/", handler.authenticate(http.HandlerFunc(handler.handleBaskets))).Methods("GET", "POST")
    router.Handle("/basket/{id}", handler.authenticate(http.HandlerFunc(handler.handleBasketByID))).Methods("GET", "PATCH", "DELETE")
    router.HandleFunc("/signup", handler.signup).Methods("POST")
    router.HandleFunc("/login", handler.login).Methods("POST")


    log.Fatal(http.ListenAndServe(":8080", router))
}

func initDB() (*sql.DB, error) {
    db, err := sql.Open("sqlite3", "shopping_cart.db")
    if err != nil {
        return nil, err
    }

    // Check if the database is accessible
    if err := db.Ping(); err != nil {
        return nil, err
    }

    // Create the users table
    createUserTableSQL := `CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );`
    if _, err := db.Exec(createUserTableSQL); err != nil {
        return nil, err
    }

    _, err = db.Exec("DROP TABLE IF EXISTS baskets")
    if err != nil {
        return nil, err
    }

    // Create the baskets table
    createBasketTableSQL := `CREATE TABLE baskets (
        id TEXT PRIMARY KEY,
        created_at DATETIME,
        updated_at DATETIME,
        data TEXT,
        state TEXT,
        user_id TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );`
    _, err = db.Exec(createBasketTableSQL)
    if err != nil {
        return nil, err
    }

    return db, nil
}

type AppHandler struct {
    DB *sql.DB
}

func (h *AppHandler) authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header is required", http.StatusUnauthorized)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        if authHeader == tokenString {
            http.Error(w, "Authorization header must be in 'Bearer <token>' format", http.StatusUnauthorized)
            return
        }

        claims := &Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
            return jwtKey, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func (h *AppHandler) handleBaskets(w http.ResponseWriter, r *http.Request) {

    ctxUserID := r.Context().Value(userIDKey)
    userID, ok := ctxUserID.(string)
    if !ok {
        http.Error(w, "User ID not found in the request context", http.StatusInternalServerError)
        return
    }

    switch r.Method {
    case "GET":
        var baskets []ShoppingCart
    
        rows, err := h.DB.Query("SELECT id, created_at, updated_at, data, state, user_id FROM baskets WHERE user_id = ?", userID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer rows.Close()
    
        for rows.Next() {
            var basket ShoppingCart
            if err := rows.Scan(&basket.ID, &basket.CreatedAt, &basket.UpdatedAt, &basket.Data, &basket.State, &basket.UserID); err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }
            baskets = append(baskets, basket)
        }
    
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(baskets)    

    case "POST":
        var newBasket ShoppingCart
        if err := json.NewDecoder(r.Body).Decode(&newBasket); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        defer r.Body.Close()
    
        newBasket.UserID = userID  
        newBasket.ID = uuid.NewString()
        currentTime := time.Now()
        newBasket.CreatedAt = currentTime
        newBasket.UpdatedAt = currentTime
    
        _, err := h.DB.Exec("INSERT INTO baskets (id, created_at, updated_at, data, state, user_id) VALUES (?, ?, ?, ?, ?, ?)",
            newBasket.ID, newBasket.CreatedAt, newBasket.UpdatedAt, newBasket.Data, newBasket.State, newBasket.UserID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    
        w.WriteHeader(http.StatusCreated)
        w.Header().Set("Content-Type", "application/json")
        
        responseBasket := ShoppingCart{
            ID: newBasket.ID,
            CreatedAt: newBasket.CreatedAt,
            UpdatedAt: newBasket.UpdatedAt,
            Data: newBasket.Data,
            State: newBasket.State,
            UserID: newBasket.UserID,
        }
        
        json.NewEncoder(w).Encode(responseBasket)    
    }
}

func (h *AppHandler) handleBasketByID(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id := vars["id"]
    basketID := vars["id"] 

    ctxUserID := r.Context().Value(userIDKey)
    userID, ok := ctxUserID.(string)
    if !ok {
        http.Error(w, "User ID not found in the request context", http.StatusInternalServerError)
        return
    }

    switch r.Method {
        
    case "GET":
        var basket ShoppingCart
        err := h.DB.QueryRow("SELECT id, created_at, updated_at, data, state FROM baskets WHERE id = ? AND user_id = ?", basketID, userID).Scan(&basket.ID, &basket.CreatedAt, &basket.UpdatedAt, &basket.Data, &basket.State)
        if err != nil {
            if err == sql.ErrNoRows {
                http.Error(w, "Basket not found or not owned by the user", http.StatusNotFound)
            } else {
                http.Error(w, err.Error(), http.StatusInternalServerError)
            }
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(basket)

    case "PATCH":
        log.Println("PATCH request received for ID:", id)
        var updateData ShoppingCart
    
        if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        defer r.Body.Close()
    

        var currentState string
        err := h.DB.QueryRow("SELECT state FROM baskets WHERE id = ? AND user_id = ?", id, userID).Scan(&currentState) 
        if err != nil {
            if err == sql.ErrNoRows {
                http.Error(w, "Basket not found or not owned by the user", http.StatusNotFound) 
            } else {
                http.Error(w, err.Error(), http.StatusInternalServerError)
            }
            return
        }
    
        if currentState == "COMPLETED" {
            http.Error(w, "Cannot update a completed basket", http.StatusForbidden)
            return
        }
    
        _, err = h.DB.Exec("UPDATE baskets SET data = ?, state = ?, updated_at = ? WHERE id = ? AND user_id = ?", 
            updateData.Data, updateData.State, time.Now(), id, userID) 
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    
        updatedRow := h.DB.QueryRow("SELECT id, created_at, updated_at, data, state FROM baskets WHERE id = ?", id)
        var updatedBasket ShoppingCart
        if err := updatedRow.Scan(&updatedBasket.ID, &updatedBasket.CreatedAt, &updatedBasket.UpdatedAt, &updatedBasket.Data, &updatedBasket.State); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(updatedBasket)    


    case "DELETE":
        log.Println("DELETE request received for ID:", id)
        
        var exists bool
        err := h.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM baskets WHERE id = ? AND user_id = ?)", id, userID).Scan(&exists) // Modified line
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        if !exists {
            http.Error(w, "Basket not found or not owned by the user", http.StatusNotFound) 
            return
        }
    
        _, err = h.DB.Exec("DELETE FROM baskets WHERE id = ? AND user_id = ?", id, userID) 
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    
        response := struct {
            Message string `json:"message"`
        }{
            Message: "Basket deleted successfully",
        }
    
        w.WriteHeader(http.StatusOK)
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)    
    }

   
}

func (h *AppHandler) signup(w http.ResponseWriter, r *http.Request) {
    var newUser User 

    err := json.NewDecoder(r.Body).Decode(&newUser)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    newUser.ID = uuid.NewString()

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }

    _, err = h.DB.Exec("INSERT INTO users (id, username, password) VALUES (?, ?, ?)", newUser.ID, newUser.Username, string(hashedPassword))
    if err != nil {
        http.Error(w, "Error creating user", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusCreated)
    fmt.Fprintln(w, "User created")
}

func (h *AppHandler) login(w http.ResponseWriter, r *http.Request) {
    log.Println("Login function called") 

    var creds User 

    err := json.NewDecoder(r.Body).Decode(&creds)
    if err != nil {
        log.Printf("Error decoding request body: %v", err) 
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    log.Printf("Credentials received: %+v", creds) 

    var hashedPassword, userID string
    err = h.DB.QueryRow("SELECT id, password FROM users WHERE username = ?", creds.Username).Scan(&userID, &hashedPassword)
    if err != nil {
        if err == sql.ErrNoRows {
            log.Println("User not found in database") 
            http.Error(w, "User not found", http.StatusUnauthorized)
        } else {
            log.Printf("Database error: %v", err) 
            http.Error(w, "Error fetching user", http.StatusInternalServerError)
        }
        return
    }

    log.Printf("User ID retrieved during login: %s", userID) 

    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(creds.Password))
    if err != nil {
        log.Println("Invalid password") 
        http.Error(w, "Invalid password", http.StatusUnauthorized)
        return
    }

    expirationTime := time.Now().Add(30 * time.Minute) 
    claims := &Claims{
        UserID: userID, 
        Username: creds.Username,
        StandardClaims: jwt.StandardClaims{
            ExpiresAt: expirationTime.Unix(),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtKey)
    if err != nil {
        http.Error(w, "Error signing token", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}
