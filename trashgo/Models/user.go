package Models

type User struct {
	IDUser      int    `json:"Id_user"`
	Email       string `gorm:"unique"`
	Password    []byte `json:"-"`
	NamaUser    string `json:"nama_user"`
	Alamat      string `json:"alamat"`
	TempatLahir string `json:"tempat_lahir"`
	Kelamin     string `json:"kelamin"`
}

type Aku struct {
	jwt.StandardClaims
	IDUser      int    `json:"Id_user"`
	Email       string `gorm:"unique"`
	NamaUser    string `json:"nama_user"`
	Alamat      string `json:"alamat"`
	TempatLahir string `json:"tempat_lahir"`
	Kelamin     string `json:"kelamin"`
}
