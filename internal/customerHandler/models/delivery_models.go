package models

type DistanceMatrixResponse struct {
	Rows []struct {
		Elements []struct {
			Distance struct {
				Text  string `json:"text"`
				Value int    `json:"value"` // Distance in meters
			} `json:"distance"`
			Duration struct {
				Text  string `json:"text"`
				Value int    `json:"value"` // Duration in seconds
			} `json:"duration"`
			Status string `json:"status"`
		} `json:"elements"`
	} `json:"rows"`
}

type DistanceRequest struct {
	Origin      string `json:"origin"`
	Destination string `json:"destination"`
}

type Item struct {
	Product  string `json:"product"`
	Quantity int    `json:"quantity"`
}

type PurchaseResponse struct {
	Message     string  `json:"message"`
	CustomerID  string  `json:"customer_id"`
	StoreID     string  `json:"store_id"`
	TotalAmount float64 `json:"total_product_cost"`
	DeliveryFee float64 `json:"delivery_fee"`
	FinalPrice  float64 `json:"final_price"`
	Items       []Item  `json:"items"`
	DistanceKm  float64 `json:"distance_km"`
}

type DistanceResponse struct {
	Origin      string  `json:"origin"`
	Destination string  `json:"destination"`
	DistanceKm  float64 `json:"distance_km"`
	Price       float64 `json:"price"`
	PricePerKm  float64 `json:"price_per_km"`
}

type VANumber struct {
	Bank     string `json:"bank"`
	VANumber string `json:"va_number"`
}
type PurchaseOnlineResponse struct {
	Message     string     `json:"message"`
	CustomerID  string     `json:"customer_id"`
	StoreID     string     `json:"store_id"`
	TotalAmount float64    `json:"total_product_cost"`
	DeliveryFee float64    `json:"delivery_fee"`
	FinalPrice  float64    `json:"final_price"`
	VaNumbers   []VANumber `json:"va_numbers"`
	DistanceKm  float64    `json:"distance_km"`
}
