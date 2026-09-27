// Synthetic gin + GORM sources used only as scanner input.

package fixtures

import (
	"log"
)

type Citizen struct {
	ID            uint   `gorm:"primaryKey"`
	EmailAddress  string `gorm:"column:email_address"`
	AadhaarNumber string `gorm:"column:aadhaar_number"`
	PanNumber     string `gorm:"column:pan_number;type:encrypted_text"`
	ExpiresAt     string `gorm:"column:expires_at"`
}

func (Citizen) TableName() string { return "citizens" }

func RegisterRoutes(router *gin.Engine) {
	router.POST("/citizens", createCitizen)
	router.GET("/citizens/:citizenId", requireAuth, readCitizen)
}

func createCitizen(c *gin.Context) {
	email_address := c.PostForm("email_address")
	log.Printf("created citizen %s", email_address)
}

func readCitizen(c *gin.Context) {}
