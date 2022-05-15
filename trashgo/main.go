package main

import (
	"fmt"
	"log"
	"strconv"
	"time"
	"trashgo/Models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	dsn := "root:@tcp(127.0.0.1:3306)/trashgo_nontps_new?charset=utf8mb4&parseTime=True&loc=Local"
	con, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("Gagal Meng koneksikan database")
	}
	fmt.Println("database terkoneksi")
	DB = con
	con.AutoMigrate(&Models.User{})
}

func Register(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return err
	}
	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)
	user := Models.User{
		Email:    data["email"],
		NamaUser: data["nama_user"],
		Password: password,
	}

	DB.Create(&user)

	return c.JSON(fiber.Map{
		"message": "Terima Kasih telah mendaftar di aplikasi kami",
	})
}

const SecretKey = "secret"

func Login(c *fiber.Ctx) error {

	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return err
	}

	var user Models.User

	DB.Where("Email = ?", data["email"]).First(&user)

	if user.IDUser == 0 {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "User not found!",
		})
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"])); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "Incorrect password!",
		})

	}
	claims := jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(user.IDUser)),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := jwtToken.SignedString([]byte(SecretKey))

	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return c.JSON(fiber.Map{
			"message": "Tidak Bisa Login!",
		})
	}

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	return c.JSON(fiber.Map{
		"message": token,
	})

	
}
func Users(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")

	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthenticated",
		})
	}
	claims := token.Claims.(*jwt.StandardClaims)

	var user Models.User

	DB.Where("Id_user = ?", claims.Issuer).First(&user)

	return c.JSON(user)

}

func Logout(c *fiber.Ctx) error {
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	return c.JSON(fiber.Map{
		"message": "success",
	})

}
func main() {

	Connect()
	app := fiber.New()
	app.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
	}))
	app.Post("/register", Register)
	app.Post("/login", Login)
	app.Get("/user", Users)
	app.Get("/logout", Logout)
	log.Fatal(app.Listen(":1234"))

}
