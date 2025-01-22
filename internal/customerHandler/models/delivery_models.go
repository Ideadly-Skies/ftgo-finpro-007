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
	//PricePerKm  float64 `json:"price_per_km"`
}
