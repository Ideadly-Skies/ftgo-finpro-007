package main

import (
	_ "ftgo-finpro/docs"
	"ftgo-finpro/config/database"
	admin_handler "ftgo-finpro/internal/adminStoreHandler"
	customer_handler "ftgo-finpro/internal/customerHandler"
	factory_handler "ftgo-finpro/internal/factoryHandler"
	cust_middleware "ftgo-finpro/internal/middleware"
	vendor_handler "ftgo-finpro/internal/vendorHandler"
	"ftgo-finpro/utils"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
)

// @title FTGO PlasCash Project
// @version 1.0
// @description API documentation for the FTGO PlashCash project.
// @termsOfService http://example.com/terms/
// @contact.Obie API Support
// @contact.url www.linkedin.com/in/obie-ananda-a87a64212 
// @contact.email Obie.kal22@gmail.com
// @license.name MIT
// @license.url http://opensource.org/licenses/MIT
// @host localhost:8080
// @BasePath /
func main() {
	// migrate data to supabase
	// config.MigrateData()

	// connect to db
	config.InitDB()
	defer config.CloseDB()

	// use echo-framework to simulate smart-city ecosystem
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Swagger route
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	// public routes
	e.POST("/customer/register", customer_handler.RegisterCustomer)
	e.POST("/customer/login", customer_handler.LoginCustomer)

	e.POST("/store-admin/register", admin_handler.RegisterStoreAdmin)
	e.POST("/store-admin/login", admin_handler.LoginStoreAdmin)

	e.POST("/vendor-admin/register", vendor_handler.RegisterVendorAdmin)
	e.POST("/vendor-admin/login", vendor_handler.LoginVendorAdmin)

	e.POST("/factory-admin/register", factory_handler.RegisterFactoryAdmin)
	e.POST("/factory-admin/login", factory_handler.LoginFactoryAdmin)

	/* protected routes for customer using JWT middleware */
	customerGroup := e.Group("/customer")
	customerGroup.Use(cust_middleware.JWTMiddleware)

	// get wallet balance for customers
	customerGroup.GET("/wallet/get-balance", customer_handler.GetWalletBalance)
	customerGroup.POST("/wallet/withdraw", customer_handler.WithdrawMoney)
	customerGroup.GET("/wallet/withdraw/status/:order_id", customer_handler.CheckWithdrawalStatus)
	customerGroup.GET("/transaction/status/:order_id", customer_handler.CheckPurchaseStatus)
	customerGroup.GET("/get-tokens", customer_handler.GetCustomerTokens)
	customerGroup.POST("/request-verify", customer_handler.RequestVerify)
	customerGroup.POST("/delivery", customer_handler.FacilitatePurchaseOnline)
	customerGroup.GET("/store-locations", customer_handler.GetAllStoreCoordinate)

	// protected routes for store admin using JWT middleware
	storeAdminGroup := e.Group("/store-admin")
	storeAdminGroup.Use(cust_middleware.JWTMiddleware)

	// facilitate purchase & recycling for customer
	storeAdminGroup.POST("/purchase", admin_handler.FacilitatePurchase)
	storeAdminGroup.POST("/recycle/:customer_id", admin_handler.RecycleMaterials)
	storeAdminGroup.POST("/redeem-token/:customer_id", admin_handler.RedeemToken)
	// Customer verification route
	storeAdminGroup.POST("/customer-verify", func(c echo.Context) error {
		// Pass `utils.SendEmailVerifNotification` as the email function dependency
		return admin_handler.VerifyCustomer(c, utils.SendEmailVerifNotification)
	})

	/* protected routes for vendor admin using JWT middleware */
	vendorAdminGroup := e.Group("/vendor-admin")
	vendorAdminGroup.Use(cust_middleware.JWTMiddleware)

	// facilitate generation of token for customer
	vendorAdminGroup.GET("/transactions", vendor_handler.GetTransactions)
	vendorAdminGroup.POST("/recycle/:transaction_id", vendor_handler.FacilitateCustomerRecycle)

	// check fill status of a particular vending machine & request pickup for payday
	vendorAdminGroup.GET("/vending-machines/:vending_machine_id/status", vendor_handler.GetVendingMachineStatus)
	vendorAdminGroup.POST("/vending-machines/:vending_machine_id/request-pickup", vendor_handler.RequestPickup)

	/* protected routes for factory admin using JWT middleware */
	factoryAdminGroup := e.Group("/factory-admin")
	factoryAdminGroup.Use(cust_middleware.JWTMiddleware)

	// process factory request
	factoryAdminGroup.POST("/process-request/:request_id", factory_handler.ProcessFactoryRequest)

	// start the server at 8080
	e.Logger.Fatal(e.Start(":8080"))
}
