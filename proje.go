package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
)

var users = make(map[string]string)
var roles = make(map[string]string)       // Kullanıcı rolleri için
var failedAttempts = make(map[string]int) // Giriş deneme sayısı
var logger *log.Logger                    // Log sistemi için

func main() {
	initLogger()
	loadFromFile() // Veri dosyadan yüklenir.

	for {
		fmt.Println("\n--- Kullanıcı Yönetim Sistemi ---")
		fmt.Println("1. Kullanıcı Ekle")
		fmt.Println("2. Kullanıcı Listele")
		fmt.Println("3. Kullanıcı Sil")
		fmt.Println("4. Giriş Yap")
		fmt.Println("5. Şifre Yenile")
		fmt.Println("6. Çıkış")
		fmt.Print("Seçiminizi yapın: ")

		var choice int
		fmt.Scan(&choice)

		switch choice {
		case 1:
			addUser()
		case 2:
			listUsers()
		case 3:
			deleteUser()
		case 4:
			loginUser()
		case 5:
			resetPassword()
		case 6:
			fmt.Println("Çıkış yapılıyor...")
			saveToFile() // Değişiklikler dosyaya kaydedilir.
			return
		default:
			fmt.Println("Geçersiz seçim, tekrar deneyin.")
		}
	}
}

// Kullanıcı ekleme
func addUser() {
	var username, password, role string
	fmt.Print("Kullanıcı adı: ")
	fmt.Scan(&username)
	fmt.Print("Şifre: ")
	fmt.Scan(&password)
	fmt.Print("Rol (admin/user): ")
	fmt.Scan(&role)

	if _, exists := users[username]; exists {
		fmt.Println("Bu kullanıcı adı zaten var.")
		return
	}

	if !isPasswordStrong(password) {
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Şifre hashlenirken bir hata oluştu:", err)
		return
	}

	users[username] = string(hashedPassword)
	roles[username] = role
	fmt.Println("Kullanıcı başarıyla eklendi.")
	logAction("Kullanıcı eklendi", username)
}

// Kullanıcı listeleme
func listUsers() {
	fmt.Println("\n--- Kayıtlı Kullanıcılar ---")
	for username, role := range roles {
		fmt.Printf("Kullanıcı adı: %s, Rol: %s\n", username, role)
	}
}

// Kullanıcı silme
func deleteUser() {
	var username, password string
	fmt.Print("Silinecek kullanıcı adı: ")
	fmt.Scan(&username)
	fmt.Print("Şifre: ")
	fmt.Scan(&password)

	if hashedPassword, exists := users[username]; exists {
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			fmt.Println("Şifre yanlış, kullanıcı silinemedi.")
			return
		}

		delete(users, username)
		delete(roles, username)
		fmt.Println("Kullanıcı başarıyla silindi.")
		logAction("Kullanıcı silindi", username)
	} else {
		fmt.Println("Kullanıcı bulunamadı.")
	}
}

// Kullanıcı giriş yapma
func loginUser() {
	var username, password string
	fmt.Print("Kullanıcı adı: ")
	fmt.Scan(&username)

	if failedAttempts[username] >= 3 {
		fmt.Println("Bu hesap kilitlendi. Lütfen yöneticiyle iletişime geçin.")
		return
	}

	fmt.Print("Şifre: ")
	fmt.Scan(&password)

	if hashedPassword, exists := users[username]; exists {
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			fmt.Println("Hatalı şifre.")
			failedAttempts[username]++
			return
		}

		fmt.Println("Giriş başarılı! Hoş geldiniz,", username)
		failedAttempts[username] = 0
		logAction("Giriş başarılı", username)
	} else {
		fmt.Println("Kullanıcı bulunamadı.")
	}
}

// Şifre yenileme
func resetPassword() {
	var username, oldPassword, newPassword string
	fmt.Print("Kullanıcı adı: ")
	fmt.Scan(&username)
	fmt.Print("Eski şifre: ")
	fmt.Scan(&oldPassword)

	if hashedPassword, exists := users[username]; exists {
		err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(oldPassword))
		if err != nil {
			fmt.Println("Eski şifre yanlış.")
			return
		}

		fmt.Print("Yeni şifre: ")
		fmt.Scan(&newPassword)
		if !isPasswordStrong(newPassword) {
			return
		}

		hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Yeni şifre hashlenirken hata oluştu:", err)
			return
		}

		users[username] = string(hashedNewPassword)
		fmt.Println("Şifre başarıyla değiştirildi.")
		logAction("Şifre yenilendi", username)
	} else {
		fmt.Println("Kullanıcı bulunamadı.")
	}
}

// Parola gücü kontrolü
func isPasswordStrong(password string) bool {
	if len(password) < 8 {
		fmt.Println("Şifre en az 8 karakter olmalıdır.")
		return false
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case (char >= '!' && char <= '/') || (char >= ':' && char <= '@') || (char >= '[' && char <= '`') || (char >= '{' && char <= '~'):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		fmt.Println("Şifre büyük harf, küçük harf, rakam ve özel karakter içermelidir.")
		return false
	}
	return true
}

// Logger başlatma
func initLogger() {
	file, err := os.OpenFile("kullanici_sistemi.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Log dosyası oluşturulamadı:", err)
		return
	}
	logger = log.New(file, "LOG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// Log kaydetme
func logAction(action, username string) {
	if logger != nil {
		logger.Printf("%s: %s\n", action, username)
	}
}

// Veri dosyadan yüklenir
func loadFromFile() {
	file, err := os.Open("users.json")
	if err != nil {
		fmt.Println("Dosya açılamadı:", err)
		return
	}
	defer file.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		fmt.Println("Veri dosyası okuma hatası:", err)
		return
	}

	// 'users' ve 'roles''i json'dan al
	if usersData, ok := data["users"].(map[string]interface{}); ok {
		for username, password := range usersData {
			users[username] = password.(string)
		}
	}

	if rolesData, ok := data["roles"].(map[string]interface{}); ok {
		for username, role := range rolesData {
			roles[username] = role.(string)
		}
	}
}

// Veri dosyaya kaydedilir
func saveToFile() {
	data := map[string]interface{}{
		"users": users,
		"roles": roles,
	}

	file, err := os.Create("users.json")
	if err != nil {
		fmt.Println("Dosya oluşturulamadı:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Daha okunabilir format için
	if err := encoder.Encode(data); err != nil {
		fmt.Println("Veri dosyaya kaydedilemedi:", err)
	}
}
