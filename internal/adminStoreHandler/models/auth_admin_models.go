package models

// StoreAdmin struct
type StoreAdmin struct {
	ID        string `json:"id"`
	StoreID   string `json:"store_id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// RegisterRequest for store admin
type RegisterRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	StoreID  string `json:"store_id" validate:"required"`
}

// LoginRequest for store admin
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse for store admin
type LoginResponse struct {
	Token string `json:"token"`
	Name  string `json:"name"`
	Email string `json:"email"`
}
