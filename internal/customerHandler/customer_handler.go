package handler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	config "ftgo-finpro/config/database"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgconn"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"

	"github.com/midtrans/midtrans-go"
	"github.com/midtrans/midtrans-go/coreapi"

	"os"
	"strings"
	"encoding/json"
)

// Customer struct
type Customer struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Email          string  `json:"email"`
	Password       string  `json:"password"`
	JwtToken       string  `json:"jwt_token"`
	WalletBalance  float64 `json:"wallet_balance"`
	TokenList      string  `json:"token_list"`
	Inventory      string  `json:"inventory"`
	IsVerified     bool    `json:"is_verified"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
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
	Token        string  `json:"token"`
	Name         string  `json:"name"`
	Email        string  `json:"email"`
	WalletBalance float64 `json:"wallet_balance"`
}

// PaymentRequest represents a request for financial transactions like withdrawals or top-ups.
type PaymentRequest struct {
    Amount float64 `json:"amount" validate:"required"`
}

// Initialize Midtrans Core API client
var coreAPI coreapi.Client

func Init() {
	// retrieve server key from .env
	ServerKey := os.Getenv("ServerKey")

	coreAPI = coreapi.Client{}
	coreAPI.New(ServerKey, midtrans.Sandbox)
}

var jwtSecret = []byte("12345")

// RegisterCustomer handles customer registration
func RegisterCustomer(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Hash the password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	// Insert into customers table
	customerQuery := "INSERT INTO customers (name, email, password) VALUES ($1, $2, $3) RETURNING id"
	var customerID string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = config.Pool.QueryRow(ctx, customerQuery, req.Name, req.Email, string(hashPassword)).Scan(&customerID)
	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Email already registered"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Customer %s registered successfully", req.Name),
		"email":   req.Email,
	})
}

// LoginCustomer handles customer login
func LoginCustomer(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Fetch customer details
	var customer Customer
	query := `SELECT id, name, email, password, wallet_balance, inventory, is_verified FROM customers WHERE email = $1`
	err := config.Pool.QueryRow(context.Background(), query, req.Email).Scan(
		&customer.ID, &customer.Name, &customer.Email, &customer.Password,
		&customer.WalletBalance, &customer.Inventory, &customer.IsVerified,
	)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(customer.Password), []byte(req.Password)); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"customer_id":   customer.ID,
		"name":          customer.Name,
		"email":         customer.Email,
		"wallet_balance": customer.WalletBalance,
		"inventory":     customer.Inventory,
		"is_verified":   customer.IsVerified,
		"exp":           jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate token"})
	}

	// Update JWT token in the database
	updateQuery := "UPDATE customers SET jwt_token = $1 WHERE id = $2"
	_, err = config.Pool.Exec(context.Background(), updateQuery, tokenString, customer.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update token"})
	}

	// Return login response
	return c.JSON(http.StatusOK, LoginResponse{
		Token:         tokenString,
		Name:          customer.Name,
		Email:         customer.Email,
		WalletBalance: customer.WalletBalance,
	})
}

func GetWalletBalance(c echo.Context) error {
	// Extract customer ID from JWT claims
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	customerID := claims["customer_id"].(string) // Use string because UUIDs are stored as strings

	// Query wallet balance
	var balance float64
	query := "SELECT wallet_balance FROM customers WHERE id = $1"
	err := config.Pool.QueryRow(context.Background(), query, customerID).Scan(&balance)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to retrieve wallet balance"})
	}

	// Return wallet balance
	return c.JSON(http.StatusOK, map[string]interface{}{
		"wallet_balance": balance,
	})
}

func WithdrawMoney(c echo.Context) error {
    // Initialize Midtrans
    Init()

    // Extract customer ID from JWT claims
    user := c.Get("user").(*jwt.Token)
    claims := user.Claims.(jwt.MapClaims)
    customerID := claims["customer_id"].(string) // UUID stored as a string
	customerName := claims["name"].(string)      // name of customer

    // Bind and validate request body
    var req PaymentRequest
    if err := c.Bind(&req); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
    }

    if req.Amount <= 0 {
        return c.JSON(http.StatusBadRequest, map[string]string{"message": "Withdraw amount must be greater than zero"})
    }

    // Generate order ID
    orderID := fmt.Sprintf("wd-%s-%d", customerID[:8], time.Now().Unix())

	// Generate Customer Field Value
	customFieldValue := fmt.Sprintf("facilitating withdraw request for %s", customerName)


    // Create a Midtrans charge request
    request := &coreapi.ChargeReq{
        PaymentType: coreapi.PaymentTypeBankTransfer,
        TransactionDetails: midtrans.TransactionDetails{
            OrderID:  orderID,
            GrossAmt: int64(req.Amount), // Midtrans uses IDR natively
        },
        BankTransfer: &coreapi.BankTransferDetails{
            Bank: midtrans.BankBca, // Use a specific bank for withdrawals
        },
		CustomField1: &customFieldValue,
	}

    // Send the charge request to Midtrans
    resp, err := coreAPI.ChargeTransaction(request)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to process withdrawal"})
    }

    // Check if VA numbers exist
    var vaNumber, bank string
    if len(resp.VaNumbers) > 0 {
        vaNumber = resp.VaNumbers[0].VANumber // Get the first VA number
        bank = resp.VaNumbers[0].Bank        // Get the bank name
    } else {
        vaNumber = "No virtual account number available" // Fallback if no VA is provided
        bank = "Unknown"
    }

    // Insert the transaction into the customer_transactions table
	transactionQuery := `
		INSERT INTO customer_transactions (customer_id, order_id, transaction_type, amount, status, created_at, updated_at)
		VALUES ($1, $2, 'Withdraw', $3, 'Pending', NOW(), NOW())
	`
	_, txnErr := config.Pool.Exec(context.Background(), transactionQuery, customerID, orderID, req.Amount)
	if txnErr != nil {
	return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to log transaction"})
	}

    // Return withdrawal details with VA number
    return c.JSON(http.StatusOK, map[string]interface{}{
        "message":        "Withdrawal initiated successfully",
        "transaction_id": resp.TransactionID,
        "order_id":       resp.OrderID,
        "va_number":      vaNumber,
        "bank":           bank,
        "gross_amount":   resp.GrossAmount,
        "status":         resp.TransactionStatus,
    })
}

// check withdrawal status for customer
func CheckWithdrawalStatus(c echo.Context) error {
	Init() // Initialize Midtrans

    orderID := c.Param("order_id") // Extract Order ID from request URL

	// Check if the transaction has already been processed
	var isProcessed bool
	checkProcessedQuery := "SELECT is_processed FROM customer_transactions WHERE order_id = $1"
	if err := config.Pool.QueryRow(context.Background(), checkProcessedQuery, orderID).Scan(&isProcessed); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to check transaction processing status"})
	}
	if isProcessed {
		return c.JSON(http.StatusConflict, map[string]string{"message": "Transaction has already been processed"})
	}

    // Fetch transaction status from Midtrans
    resp, err := coreAPI.CheckTransaction(orderID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch transaction status"})
    }

    // Update transaction status in the database
    updateQuery := "UPDATE customer_transactions SET status = $1, updated_at = NOW() WHERE order_id = $2"
    _, dbErr := config.Pool.Exec(context.Background(), updateQuery, resp.TransactionStatus, orderID)
    if dbErr != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update transaction status"})
    }

    // If the transaction is successful, update the customer's wallet balance
    if resp.TransactionStatus == "settlement" {
        // Get the transaction amount and customer ID from the database
        var amount float64
        var customerID string
        selectQuery := "SELECT amount, customer_id FROM customer_transactions WHERE order_id = $1"
        row := config.Pool.QueryRow(context.Background(), selectQuery, orderID)
        if err := row.Scan(&amount, &customerID); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch transaction details"})
        }

        // Add the transaction amount to the customer's wallet balance
        updateWalletBalance := "UPDATE customers SET wallet_balance = wallet_balance + $1 WHERE id = $2"
        _, err := config.Pool.Exec(context.Background(), updateWalletBalance, amount, customerID)
        if err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update wallet balance"})
        }

		// Mark the transaction as processed
        markProcessedQuery := "UPDATE customer_transactions SET is_processed = TRUE WHERE order_id = $1"
        _, dbErr = config.Pool.Exec(context.Background(), markProcessedQuery, orderID)
        if dbErr != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to mark transaction as processed"})
        }
    }

    // Return the transaction status
    return c.JSON(http.StatusOK, map[string]interface{}{
        "order_id":       resp.OrderID,
        "transaction_id": resp.TransactionID,
        "status":         resp.TransactionStatus,
        "payment_type":   resp.PaymentType,
        "gross_amount":   resp.GrossAmount,
    })
}

func CheckPurchaseStatus(c echo.Context) error {
    Init() // Initialize Midtrans

    orderID := c.Param("order_id") // Extract Order ID from the request URL

	// Check if the transaction has already been processed
	var isProcessed bool
	checkProcessedQuery := "SELECT is_processed FROM customer_transactions WHERE order_id = $1"
	if err := config.Pool.QueryRow(context.Background(), checkProcessedQuery, orderID).Scan(&isProcessed); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to check transaction processing status"})
	}
	if isProcessed {
		return c.JSON(http.StatusConflict, map[string]string{"message": "Transaction has already been processed"})
	}

    // Fetch transaction status from Midtrans
    resp, err := coreAPI.CheckTransaction(orderID)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch transaction status"})
    }

    // Update the customer_transactions table with the latest status
    updateCustomerTransactionQuery := "UPDATE customer_transactions SET status = $1, updated_at = NOW() WHERE order_id = $2"
    _, dbErr := config.Pool.Exec(context.Background(), updateCustomerTransactionQuery, resp.TransactionStatus, orderID)
    if dbErr != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update customer transaction status"})
    }

    // If the transaction is successful, process the purchase
    if resp.TransactionStatus == "settlement" {
		// Parse purchased items from CustomField1
		purchasedItems := []struct {
			Product  string `json:"product"`
			Quantity int    `json:"quantity"`
		}{}
		itemDescription := resp.CustomField1
		if itemDescription == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Item details missing from transaction"})
		}
		items := strings.Split(itemDescription, ", ")
		fmt.Println("items: ", items) // Debugging log to check the items array

		for _, item := range items {
			// Find the last space and separate product name and quantity
			splitIndex := strings.LastIndex(item, " ")
			if splitIndex == -1 || !strings.HasSuffix(item, "x") {
				fmt.Printf("Error parsing item: %s\n", item)
				continue // Skip invalid items
			}

			product := item[:splitIndex] // Everything before the last space
			quantityStr := item[splitIndex+1:] // Everything after the last space
			var quantity int
			_, err := fmt.Sscanf(quantityStr, "%dx", &quantity) // Parse the quantity with the "x" suffix
			if err != nil {
				fmt.Printf("Error parsing quantity from item: %s, error: %v\n", item, err)
				continue // Skip invalid items
			}

			purchasedItems = append(purchasedItems, struct {
				Product  string `json:"product"`
				Quantity int    `json:"quantity"`
			}{Product: product, Quantity: quantity})
		}

		fmt.Println("items: ", items)
		fmt.Println("purchased items: ", purchasedItems)

        // Fetch the store ID from CustomField2
        storeID := resp.CustomField2
        if storeID == "" {
            return c.JSON(http.StatusBadRequest, map[string]string{"message": "Store ID missing from transaction"})
        }

        // Fetch the customer ID from the customer_transactions table
        var customerID string
        fetchCustomerIDQuery := "SELECT customer_id FROM customer_transactions WHERE order_id = $1"
        if err := config.Pool.QueryRow(context.Background(), fetchCustomerIDQuery, orderID).Scan(&customerID); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch customer ID"})
        }

        // Log the transaction in the store_transactions table
        totalAmount := resp.GrossAmount
        transactionQuery := `
            INSERT INTO store_transactions (customer_id, store_id, items, total_amount, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, 'Completed', NOW(), NOW())
        `
        itemsJSON, _ := json.Marshal(purchasedItems)
        if _, err := config.Pool.Exec(context.Background(), transactionQuery, customerID, storeID, itemsJSON, totalAmount); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to record transaction in store_transactions"})
        }

        // Update the store inventory
        var storeProducts []struct {
            Product  string  `json:"product"`
            Price    float64 `json:"price"`
            Quantity int     `json:"quantity"`
        }
        fetchStoreInventoryQuery := "SELECT products FROM stores WHERE id = $1"
        var storeProductsJSON []byte
        if err := config.Pool.QueryRow(context.Background(), fetchStoreInventoryQuery, storeID).Scan(&storeProductsJSON); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch store inventory"})
        }
        if err := json.Unmarshal(storeProductsJSON, &storeProducts); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse store inventory"})
        }

        for _, purchasedItem := range purchasedItems {
            for i, storeProduct := range storeProducts {
                if storeProduct.Product == purchasedItem.Product {
                    storeProducts[i].Quantity -= purchasedItem.Quantity
                    break
                }
            }
        }

        updatedStoreProductsJSON, _ := json.Marshal(storeProducts)
        updateStoreInventoryQuery := "UPDATE stores SET products = $1 WHERE id = $2"
        _, execErr := config.Pool.Exec(context.Background(), updateStoreInventoryQuery, updatedStoreProductsJSON, storeID)
        if execErr != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update store inventory"})
        }

        // Update the customer inventory
        var customerInventory []struct {
            Product  string `json:"product"`
            Quantity int    `json:"quantity"`
        }
        fetchCustomerInventoryQuery := "SELECT inventory FROM customers WHERE id = $1"
        var customerInventoryJSON []byte
        if err := config.Pool.QueryRow(context.Background(), fetchCustomerInventoryQuery, customerID).Scan(&customerInventoryJSON); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch customer inventory"})
        }
        if err := json.Unmarshal(customerInventoryJSON, &customerInventory); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse customer inventory"})
        }

        for _, purchasedItem := range purchasedItems {
            found := false
            for i, inventoryItem := range customerInventory {
                if inventoryItem.Product == purchasedItem.Product {
                    customerInventory[i].Quantity += purchasedItem.Quantity
                    found = true
                    break
                }
            }
            if !found {
                customerInventory = append(customerInventory, struct {
                    Product  string `json:"product"`
                    Quantity int    `json:"quantity"`
                }{Product: purchasedItem.Product, Quantity: purchasedItem.Quantity})
            }
        }

        updatedCustomerInventoryJSON, _ := json.Marshal(customerInventory)
        updateCustomerInventoryQuery := "UPDATE customers SET inventory = $1 WHERE id = $2"
        _, dbErr := config.Pool.Exec(context.Background(), updateCustomerInventoryQuery, updatedCustomerInventoryJSON, customerID)
        if dbErr != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update customer inventory"})
        }

		// Mark the transaction as processed
        markProcessedQuery := "UPDATE customer_transactions SET is_processed = TRUE WHERE order_id = $1"
        _, dbErr = config.Pool.Exec(context.Background(), markProcessedQuery, orderID)
        if dbErr != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to mark transaction as processed"})
        }
    }

    // Return the transaction status
    return c.JSON(http.StatusOK, map[string]interface{}{
        "order_id":       resp.OrderID,
        "transaction_id": resp.TransactionID,
        "status":         resp.TransactionStatus,
        "payment_type":   resp.PaymentType,
        "gross_amount":   resp.GrossAmount,
    })
}
