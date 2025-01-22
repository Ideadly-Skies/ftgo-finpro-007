package models

// Customer struct
type Customer struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Email         string  `json:"email"`
	Password      string  `json:"password"`
	JwtToken      string  `json:"jwt_token"`
	WalletBalance float64 `json:"wallet_balance"`
	TokenList     string  `json:"token_list"`
	Inventory     string  `json:"inventory"`
	IsVerified    bool    `json:"is_verified"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// RegisterRequest struct
type RegisterRequest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginRequest struct
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse struct
type LoginResponse struct {
	Token         string  `json:"token"`
	Name          string  `json:"name"`
	Email         string  `json:"email"`
	WalletBalance float64 `json:"wallet_balance"`
}
