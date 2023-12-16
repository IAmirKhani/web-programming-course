package main

import (
    "time"
    
)

type ShoppingCart struct {
    ID         string    `json:"id"`
    CreatedAt  time.Time `json:"created_at"`
    UpdatedAt  time.Time `json:"updated_at"`
    Data       string    `json:"data"`
    State      string    `json:"state"`
    UserID     string    `json:"user_id"` 
}

type User struct {
    ID       string `json:"id"`
    Username string `json:"username"`
    Password string `json:"password"`
}

