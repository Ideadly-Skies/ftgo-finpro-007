package Handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"ftgo-finpro/config/database"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgconn"
	"github.com/labstack/echo/v4"

	"github.com/midtrans/midtrans-go"
	"github.com/midtrans/midtrans-go/coreapi"
	"strings"
	"os"
)

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

var jwtSecret = []byte("12345")

// Initialize Midtrans Core API client
var coreAPI coreapi.Client

func Init() {
	// retrieve server key from .env
	ServerKey := os.Getenv("ServerKey")

	coreAPI = coreapi.Client{}
	coreAPI.New(ServerKey, midtrans.Sandbox)
}

// RegisterStoreAdmin handles store admin registration
func RegisterStoreAdmin(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Hash the password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	// Insert into store_admins table
	adminQuery := "INSERT INTO store_admins (name, email, password, store_id) VALUES ($1, $2, $3, $4) RETURNING id"
	var adminID string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = config.Pool.QueryRow(ctx, adminQuery, req.Name, req.Email, string(hashPassword), req.StoreID).Scan(&adminID)
	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Email already registered"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Internal Server Error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": fmt.Sprintf("Store admin %s registered successfully", req.Name),
		"email":   req.Email,
	})
}

// LoginStoreAdmin handles store admin login
func LoginStoreAdmin(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid Request"})
	}

	// Fetch admin details
	var admin StoreAdmin
	query := `SELECT id, store_id, name, email, password FROM store_admins WHERE email = $1`
	err := config.Pool.QueryRow(context.Background(), query, req.Email).Scan(
		&admin.ID, &admin.StoreID, &admin.Name, &admin.Email, &admin.Password,
	)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(req.Password)); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid email or password"})
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"admin_id": admin.ID,
		"name":     admin.Name,
		"email":    admin.Email,
		"store_id": admin.StoreID,
		"exp":      jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to generate token"})
	}

	// Update the JWT token in the database
	updateQuery := "UPDATE store_admins SET jwt_token = $1 WHERE id = $2"
	_, err = config.Pool.Exec(context.Background(), updateQuery, tokenString, admin.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update token"})
	}

	// Return login response
	return c.JSON(http.StatusOK, LoginResponse{
		Token: tokenString,
		Name:  admin.Name,
		Email: admin.Email,
	})
}

func FacilitatePurchase(c echo.Context) error {
    // Extract admin claims
    admin := c.Get("user").(*jwt.Token)
    adminClaims := admin.Claims.(jwt.MapClaims)
    storeID := adminClaims["store_id"].(string)

    // Bind the purchase request
    var req struct {
        CustomerID     string `json:"customer_id" validate:"required"`
        Items          []struct {
            Product  string  `json:"product" validate:"required"`
            Quantity int     `json:"quantity" validate:"required,min=1"`
        } `json:"items" validate:"required"`
        PaymentMethod string `json:"payment_method" validate:"required"` // "Wallet" or "Online"
    }
    
	if err := c.Bind(&req); err != nil || len(req.Items) == 0 {
        return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request"})
    }

    // Fetch store inventory
    var storeProducts []struct {
        Product  string  `json:"product"`
        Price    float64 `json:"price"`
        Weight   float64 `json:"weight"` // include weight in here
        Quantity int     `json:"quantity"`
    }
    var productTypes []string

    storeQuery := "SELECT products, product_types FROM stores WHERE id = $1"
    var storeProductsJSON, productTypesJSON []byte
    if err := config.Pool.QueryRow(context.Background(), storeQuery, storeID).Scan(&storeProductsJSON, &productTypesJSON); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch store inventory"})
    }
    if err := json.Unmarshal(storeProductsJSON, &storeProducts); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse store inventory"})
    }
    if err := json.Unmarshal(productTypesJSON, &productTypes); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse product types"})
    }

    // Create a map of product types
    productTypeMap := make(map[string]string)
    for i, product := range storeProducts {
        if i < len(productTypes) {
            productTypeMap[product.Product] = productTypes[i]
        }
    }

    // Verify item availability and calculate total cost
    calculatedTotalCost := 0.0
    var itemDescriptions []string
    for _, item := range req.Items {
        for i, product := range storeProducts {
            if product.Product == item.Product {
                if product.Quantity < item.Quantity {
                    return c.JSON(http.StatusBadRequest, map[string]string{
                        "message": fmt.Sprintf("Insufficient stock for %s", item.Product),
                    })
                }
                // Reduce the quantity and retain the weight
                storeProducts[i].Quantity -= item.Quantity

                // Add the cost for this item to the total
                calculatedTotalCost += product.Price * float64(item.Quantity)

                // Add description for Midtrans payload
                itemDescriptions = append(itemDescriptions, fmt.Sprintf("%s x%d", product.Product, item.Quantity))
                break
            }
        }
    }
 
    if req.PaymentMethod == "Wallet" {
        // Wallet Payment Logic
        var customerBalance float64
        balanceQuery := "SELECT wallet_balance FROM customers WHERE id = $1"
        if err := config.Pool.QueryRow(context.Background(), balanceQuery, req.CustomerID).Scan(&customerBalance); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch customer wallet balance"})
        }
        if customerBalance < calculatedTotalCost {
            return c.JSON(http.StatusBadRequest, map[string]string{"message": "Insufficient wallet balance"})
        }

        // Deduct wallet balance
        updateWalletQuery := "UPDATE customers SET wallet_balance = wallet_balance - $1 WHERE id = $2"
        if _, err := config.Pool.Exec(context.Background(), updateWalletQuery, calculatedTotalCost, req.CustomerID); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update customer wallet balance"})
        }

		// Generate a unique order ID for the wallet transaction
		orderID := fmt.Sprintf("wallet-%s-%d", req.CustomerID[:8], time.Now().Unix())

		// Insert transaction into the customer_transactions table
		customerTransactionQuery := `
			INSERT INTO customer_transactions (id, customer_id, order_id, transaction_type, amount, status, is_processed, created_at, updated_at)
			VALUES (gen_random_uuid(), $1, $2, 'Purchase', $3, 'Completed', TRUE, NOW(), NOW())
		`
		if _, err := config.Pool.Exec(context.Background(), customerTransactionQuery, req.CustomerID, orderID, calculatedTotalCost); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to log transaction in customer_transactions"})
		}
			
    } else if req.PaymentMethod == "Online" {
		Init()

		// Generate Order ID
		orderID := fmt.Sprintf("store-%s-%d", storeID[:8], time.Now().Unix())

		// Create a description for Midtrans
		description := strings.Join(itemDescriptions, ", ")

		// Create a Midtrans charge request
		request := &coreapi.ChargeReq{
			PaymentType: coreapi.PaymentTypeBankTransfer,
			TransactionDetails: midtrans.TransactionDetails{
				OrderID:  orderID,
				GrossAmt: int64(calculatedTotalCost),
			},
			BankTransfer: &coreapi.BankTransferDetails{
				Bank: midtrans.BankBca,
			},
			CustomField1: &description, // Include item descriptions here
			CustomField2: &storeID,     // Store ID
		}

		// Send the charge request to Midtrans
		resp, err := coreAPI.ChargeTransaction(request)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to process online payment"})
		}

		if resp.TransactionStatus != "pending" {
			return c.JSON(http.StatusBadRequest, map[string]string{"message": "Payment not authorized"})
		}

		// Log the transaction as pending in customer_transactions table
		transactionQuery := `
			INSERT INTO customer_transactions (customer_id, order_id, transaction_type, amount, status, created_at, updated_at)
			VALUES ($1, $2, 'Purchase', $3, 'Pending', NOW(), NOW())
		`
		if _, err := config.Pool.Exec(context.Background(), transactionQuery, req.CustomerID, orderID, calculatedTotalCost); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to log transaction"})
		}
		
		// Return response
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":        "Purchase initiated successfully",
			"order_id":       orderID,
			"va_numbers":     resp.VaNumbers,
			"total_amount":   calculatedTotalCost,
			"transaction_id": resp.TransactionID,
		})
    }

    // Update store inventory
    updatedStoreProductsJSON, _ := json.Marshal(storeProducts)
    updateStoreQuery := "UPDATE stores SET products = $1 WHERE id = $2"
    if _, err := config.Pool.Exec(context.Background(), updateStoreQuery, updatedStoreProductsJSON, storeID); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{
            "message": "Failed to update store inventory",
        })
    } 

    // Update customer's inventory
    var customerInventory []struct {
        Product  string     `json:"product"`
        Quantity int        `json:"quantity"`
        Weight   float64    `json:"weight"`
        Type     string  `json:"type"` 
    }
    customerInventoryQuery := "SELECT inventory FROM customers WHERE id = $1"
    var customerInventoryJSON []byte
    if err := config.Pool.QueryRow(context.Background(), customerInventoryQuery, req.CustomerID).Scan(&customerInventoryJSON); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch customer inventory"})
    }
    if err := json.Unmarshal(customerInventoryJSON, &customerInventory); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse customer inventory"})
    }
    for _, item := range req.Items {
        found := false
        for i, inventoryItem := range customerInventory {
            if inventoryItem.Product == item.Product {
                // Update existing inventory item
                for _, product := range storeProducts {
                    if product.Product == item.Product {
                        customerInventory[i].Quantity += item.Quantity
                        customerInventory[i].Weight += float64(item.Quantity) * product.Weight
                        break
                    }
                }
                found = true
                break
            }
        }
        if !found {
            // Add a new item to the inventory
            for _, product := range storeProducts {
                if product.Product == item.Product {
                    customerInventory = append(customerInventory, struct {
                        Product  string  `json:"product"`
                        Quantity int     `json:"quantity"`
                        Weight   float64 `json:"weight"`
                        Type     string  `json:"type"`
                    }{
                        Product:  item.Product,
                        Quantity: item.Quantity,
                        Weight:   float64(item.Quantity) * product.Weight,
                        Type:     productTypeMap[item.Product],
                    })
                    break
                }
            }
        }
    }

    updatedCustomerInventoryJSON, _ := json.Marshal(customerInventory)
    updateCustomerInventoryQuery := "UPDATE customers SET inventory = $1 WHERE id = $2"
    if _, err := config.Pool.Exec(context.Background(), updateCustomerInventoryQuery, updatedCustomerInventoryJSON, req.CustomerID); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update customer inventory"})
    }

    // Insert transaction into store_transactions table (only for wallet payments)
    if req.PaymentMethod == "Wallet" {
        transactionQuery := `
            INSERT INTO store_transactions (customer_id, store_id, items, total_amount, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, 'Completed', NOW(), NOW())
        `
        itemsJSON, _ := json.Marshal(req.Items)
        if _, err := config.Pool.Exec(context.Background(), transactionQuery, req.CustomerID, storeID, itemsJSON, calculatedTotalCost); err != nil {
            return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to record transaction"})
        }
    }

    // Return success response
    return c.JSON(http.StatusOK, map[string]interface{}{
        "message":      "Purchase successful",
        "customer_id":  req.CustomerID,
        "store_id":     storeID,
        "total_amount": calculatedTotalCost,
        "items":        req.Items,
    })
}

func RecycleMaterials(c echo.Context) error {
    // Extract admin claims from the JWT
    admin := c.Get("user").(*jwt.Token)
    adminClaims := admin.Claims.(jwt.MapClaims)
    storeID := adminClaims["store_id"].(string)
    adminID := adminClaims["admin_id"].(string)

    // Extract customer ID from request parameters
    customerID := c.Param("customer_id")

    // Bind request payload for products and quantities
    var requestItems []struct {
        Product  string `json:"product" validate:"required"`
        Quantity int    `json:"quantity" validate:"required,min=1"`
    }
    if err := c.Bind(&requestItems); err != nil {
        return c.JSON(http.StatusBadRequest, map[string]string{"message": "Invalid request format"})
    }

    // Fetch vending machine details
    var compatiblePlastics []string
    var weightLimit, currentWeight float64
    var currentFill int
    vendingMachineQuery := `SELECT compatible_plastics, weight_limit, current_weight, current_fill FROM vending_machines WHERE store_id = $1 LIMIT 1`
    var plasticsJSON []byte
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := config.Pool.QueryRow(ctx, vendingMachineQuery, storeID).Scan(&plasticsJSON, &weightLimit, &currentWeight, &currentFill); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch vending machine details"})
    }

    if err := json.Unmarshal(plasticsJSON, &compatiblePlastics); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse compatible plastics"})
    }

    // Fetch customer inventory
    var customerInventory []struct {
        Product  string  `json:"product"`
        Quantity int     `json:"quantity"`
        Weight   float64 `json:"weight"`
        Type     string  `json:"type"`
    }
    inventoryQuery := `SELECT inventory FROM customers WHERE id = $1`
    var inventoryJSON []byte
    if err := config.Pool.QueryRow(ctx, inventoryQuery, customerID).Scan(&inventoryJSON); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to fetch customer inventory"})
    }
    if err := json.Unmarshal(inventoryJSON, &customerInventory); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to parse customer inventory"})
    }

    // Process recycling request
    var recyclableMaterials []struct {
        Product  string  `json:"product"`
        Quantity int     `json:"quantity"`
        Weight   float64 `json:"weight"`
        Type     string  `json:"type"`
    }
    totalWeight := 0.0
    totalItems := 0

    for _, reqItem := range requestItems {
        matched := false
        for i, inventoryItem := range customerInventory {
            if reqItem.Product == inventoryItem.Product {
                // Calculate weight for requested quantity
                itemWeight := float64(reqItem.Quantity) * (inventoryItem.Weight / float64(inventoryItem.Quantity))
                if currentWeight+itemWeight > weightLimit {
                    return c.JSON(http.StatusBadRequest, map[string]string{
                        "message": fmt.Sprintf("Recycling cannot proceed: weight limit exceeded. Current weight: %.2fkg, Limit: %.2fkg", currentWeight, weightLimit),
                    })
                }
                if inventoryItem.Quantity < reqItem.Quantity {
                    return c.JSON(http.StatusBadRequest, map[string]string{
                        "message": fmt.Sprintf("Insufficient quantity for product: %s", reqItem.Product),
                    })
                }

                // Check compatibility
                for _, compatible := range compatiblePlastics {
                    if inventoryItem.Type == compatible {
                        // Update customer inventory
                        customerInventory[i].Quantity -= reqItem.Quantity
                        currentWeight += itemWeight
                        currentFill += reqItem.Quantity

                        recyclableMaterials = append(recyclableMaterials, struct {
                            Product  string  `json:"product"`
                            Quantity int     `json:"quantity"`
                            Weight   float64 `json:"weight"`
                            Type     string  `json:"type"`
                        }{
                            Product: reqItem.Product, 
                            Quantity: reqItem.Quantity, 
                            Weight: itemWeight, 
                            Type: compatible,
                        })

                        totalWeight += itemWeight
                        totalItems += reqItem.Quantity
                        matched = true
                        break
                    }
                }
            }
        }
        if !matched {
            return c.JSON(http.StatusBadRequest, map[string]string{
                "message": fmt.Sprintf("Product not recyclable or incompatible: %s", reqItem.Product),
            })
        }
    }

    // Update vending machine
    updateVendingMachineQuery := `
        UPDATE vending_machines 
        SET current_weight = $1, current_fill = $2, updated_at = NOW() 
        WHERE store_id = $3`
    if _, err := config.Pool.Exec(ctx, updateVendingMachineQuery, currentWeight, currentFill, storeID); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update vending machine"})
    }

    // Log the transaction in the vending_transactions table
    transactionQuery := `
        INSERT INTO vending_transactions 
        (customer_id, store_admin_id, vendor_id, materials, number_of_items, total_weight, created_at, updated_at, is_processed)
        VALUES ($1, $2, (SELECT vendor_id FROM vending_machines WHERE store_id = $3 LIMIT 1), $4, $5, $6, NOW(), NOW(), FALSE)
    `
    recyclableMaterialsJSON, _ := json.Marshal(recyclableMaterials)
    if _, err := config.Pool.Exec(ctx, transactionQuery, customerID, adminID, storeID, recyclableMaterialsJSON, totalItems, totalWeight); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to log transaction"})
    }

    // Update customer inventory
    updatedInventoryJSON, _ := json.Marshal(customerInventory)
    updateInventoryQuery := `UPDATE customers SET inventory = $1 WHERE id = $2`
    if _, err := config.Pool.Exec(ctx, updateInventoryQuery, updatedInventoryJSON, customerID); err != nil {
        return c.JSON(http.StatusInternalServerError, map[string]string{"message": "Failed to update customer inventory"})
    }

    // Respond with success
    return c.JSON(http.StatusOK, map[string]interface{}{
        "message":             "Materials recycled successfully",
        "total_items":         totalItems,
        "total_weight":        totalWeight,
        "recyclable_materials": recyclableMaterials,
        "current_fill":        currentFill,
        "current_weight":      currentWeight,
        "weight_limit":        weightLimit,
    })
}