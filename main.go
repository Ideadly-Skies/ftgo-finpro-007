package main

import (
	"ftgo-finpro/config/database"
	customer_handler "ftgo-finpro/internal/customerHandler"
	cust_middleware "ftgo-finpro/internal/middleware"
	admin_handler "ftgo-finpro/internal/adminStoreHandler"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main(){
	// migrate data to supabase
	config.MigrateData()

	// connect to db
	config.InitDB()
	defer config.CloseDB()
	
	// use echo-framework to simulate smart-city ecosystem
	e := echo.New()
	
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	
	// public routes 
	e.POST("/customer/register", customer_handler.RegisterCustomer)
	e.POST("/customer/login", customer_handler.LoginCustomer)

	e.POST("/store-admin/register", admin_handler.RegisterStoreAdmin)
	e.POST("/store-admin/login", admin_handler.LoginStoreAdmin)

	// protected routes for customer using JWT middleware
	customerGroup := e.Group("/customer")
	customerGroup.Use(cust_middleware.JWTMiddleware)

	// get wallet balance for customers
	customerGroup.GET("/wallet/get-balance", customer_handler.GetWalletBalance)
	customerGroup.POST("/wallet/withdraw", customer_handler.WithdrawMoney)
	customerGroup.GET("/wallet/withdraw/status/:order_id", customer_handler.CheckWithdrawalStatus)
	customerGroup.GET("/transaction/status/:order_id", customer_handler.CheckPurchaseStatus)

	// protected routes for admin using JWT middleware
	adminGroup := e.Group("/store-admin")
	adminGroup.Use(cust_middleware.JWTMiddleware)

	// facilitate purchase for customer
	adminGroup.POST("/purchase", admin_handler.FacilitatePurchase)

	// start the server at 8080
	e.Logger.Fatal(e.Start(":8080"))
}