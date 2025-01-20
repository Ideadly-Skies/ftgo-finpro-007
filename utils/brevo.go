package utils

import (
	"bytes"
	"errors"
	"log"
	"os"
	"text/template"

	brevo "github.com/sendinblue/APIv3-go-library/v2/lib"
)

func SendRegisterNotification(email, name string) error {
	// Get Brevo API Key from environment
	apiKey := os.Getenv("BREVO_API_KEY")
	if apiKey == "" {
		return errors.New("brevo API Key not found in environment")
	}

	// Set up Brevo API client
	cfg := brevo.NewConfiguration()
	cfg.AddDefaultHeader("api-key", apiKey)
	client := brevo.NewAPIClient(cfg)

	// Read HTML content from file
	htmlFilePath := "utils/html/user_register.html"
	emailTemplate, err := os.ReadFile(htmlFilePath)
	if err != nil {
		log.Printf("Error reading HTML file: %v", err)
		return err
	}

	// Parse the HTML content as a template
	tmpl, err := template.New("emailTemplate").Parse(string(emailTemplate))
	if err != nil {
		log.Printf("Error parsing HTML template: %v", err)
		return err
	}

	// Create a map to hold the variables for the template
	data := map[string]interface{}{
		"Name":  name,
		"Email": email,
	}

	// Use bytes.Buffer to capture the output of the template execution
	var bodyContent bytes.Buffer
	err = tmpl.Execute(&bodyContent, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		return err
	}

	// Create Brevo email struct
	sender := &brevo.SendSmtpEmailSender{
		Name:  "PlasCash Team",
		Email: "bot.plascash@outlook.com",
	}

	to := []brevo.SendSmtpEmailTo{
		{Name: name, Email: email},
	}

	// Create the email with HTML content
	emailRequest := &brevo.SendSmtpEmail{
		Sender:      sender,
		To:          to,
		Subject:     "Welcome to PlasCash!",
		HtmlContent: bodyContent.String(),
	}

	// Send email using Brevo API
	_, resp, err := client.TransactionalEmailsApi.SendTransacEmail(nil, *emailRequest)
	if err != nil {
		log.Printf("Error while sending email: %v", err)
		return err
	}

	log.Printf("Email sent successfully! Response: %v", resp)
	return nil
}

func SendEmailNotification(email, name string) error {
	// Get Brevo API Key from environment
	apiKey := os.Getenv("BREVO_API_KEY")
	if apiKey == "" {
		return errors.New("brevo API Key not found in environment")
	}

	// Set up Brevo API client
	cfg := brevo.NewConfiguration()
	cfg.AddDefaultHeader("api-key", apiKey)
	client := brevo.NewAPIClient(cfg)

	// Read HTML content from file
	htmlFilePath := "utils/html/store_admin.html"
	emailTemplate, err := os.ReadFile(htmlFilePath)
	if err != nil {
		log.Printf("Error reading HTML file: %v", err)
		return err
	}

	// Parse the HTML content as a template
	tmpl, err := template.New("emailTemplate").Parse(string(emailTemplate))
	if err != nil {
		log.Printf("Error parsing HTML template: %v", err)
		return err
	}

	// Create a map to hold the variables for the template
	data := map[string]interface{}{
		"Name":  name,
		"Email": email,
	}

	// Use bytes.Buffer to capture the output of the template execution
	var bodyContent bytes.Buffer
	err = tmpl.Execute(&bodyContent, data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		return err
	}

	// Create Brevo email struct
	sender := &brevo.SendSmtpEmailSender{
		Name:  "PlasCash Team",
		Email: "bot.plascash@outlook.com",
	}

	to := []brevo.SendSmtpEmailTo{
		{Name: "Store Admin", Email: "sa.plascash@gmail.com"},
	}

	// Create the email with HTML content
	emailRequest := &brevo.SendSmtpEmail{
		Sender:      sender,
		To:          to,
		Subject:     "Hello, Store Admin!",
		HtmlContent: bodyContent.String(),
	}

	// Send email using Brevo API
	_, resp, err := client.TransactionalEmailsApi.SendTransacEmail(nil, *emailRequest)
	if err != nil {
		log.Printf("Error while sending email: %v", err)
		return err
	}

	log.Printf("Email sent successfully! Response: %v", resp)
	return nil
}

func SendEmailVerifNotification(email string) error {
	// Get Brevo API Key from environment
	apiKey := os.Getenv("BREVO_API_KEY")
	if apiKey == "" {
		return errors.New("brevo API Key not found in environment")
	}

	// Set up Brevo API client
	cfg := brevo.NewConfiguration()
	cfg.AddDefaultHeader("api-key", apiKey)
	client := brevo.NewAPIClient(cfg)

	// Read HTML content from file
	htmlFilePath, err := os.ReadFile("utils/html/verify.html")
	if err != nil {
		log.Printf("Error reading HTML file: %v", err)
		return err
	}

	// Create Brevo email struct
	sender := &brevo.SendSmtpEmailSender{
		Name:  "PlasCash Team",
		Email: "bot.plascash@outlook.com",
	}

	to := []brevo.SendSmtpEmailTo{
		{Email: email},
	}

	// Create the email with HTML content
	emailRequest := &brevo.SendSmtpEmail{
		Sender:      sender,
		To:          to,
		Subject:     "Hello",
		HtmlContent: string(htmlFilePath),
	}

	// Send email using Brevo API
	_, resp, err := client.TransactionalEmailsApi.SendTransacEmail(nil, *emailRequest)
	if err != nil {
		log.Printf("Error while sending email: %v", err)
		return err
	}

	log.Printf("Email sent successfully! Response: %v", resp)
	return nil
}
