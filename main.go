package main

import (
	"ftgo-finpro/config/database"
	admin_handler "ftgo-finpro/internal/adminStoreHandler"
	customer_handler "ftgo-finpro/internal/customerHandler"
	factory_handler "ftgo-finpro/internal/factoryHandler"
	cust_middleware "ftgo-finpro/internal/middleware"
	vendor_handler "ftgo-finpro/internal/vendorHandler"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
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
	//customerGroup.POST("/purchase", customer_handler.FacilitatePurchaseWithDistance)

	// protected routes for store admin using JWT middleware
	storeAdminGroup := e.Group("/store-admin")
	storeAdminGroup.Use(cust_middleware.JWTMiddleware)

	// facilitate purchase & recycling for customer
	storeAdminGroup.POST("/purchase", admin_handler.FacilitatePurchase)
	storeAdminGroup.POST("/recycle/:customer_id", admin_handler.RecycleMaterials)
	storeAdminGroup.POST("/redeem-token/:customer_id", admin_handler.RedeemToken)
	storeAdminGroup.POST("/customer-verify", admin_handler.VerifyCustomer)

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
