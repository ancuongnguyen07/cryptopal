package set2

import (
	"cryptopal/set1"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type User struct {
	Email string
	UID   int
	Role  string
}

// String() method for `User`.
// Return the raw representing string of the User instance.
func (u User) String() string {
	return fmt.Sprintf("{\n\tEmail: %s,\n\tUID: %d,\n\tRole: %s\n}", u.Email, u.UID, u.Role)
}

// Encode() returns the encoded representing string of the User instance.
// For example:
//
//	{
//		email: 'foo@bar.com',
//		uid: 10,
//		role: 'user'
//	}
//
// ---> email=foo@bar.com&uid=10&role=user
func (u User) Encode() string {
	return fmt.Sprintf("email=%s&uid=%d&role=%s", u.Email, u.UID, u.Role)
}

// Parse `foo=bar&baz=qux&zap=zazzle` into:
//
//	{
//	 foo: 'bar',
//	 baz: 'qux',
//	 zap: 'zazzle'
//	}
func parseToUser(entry string) (User, error) {
	fields := strings.Split(entry, "&")
	var user User
	for _, f := range fields {
		vars := strings.Split(f, "=")
		// if len(vars) != 2 {
		// 	return User{}, errors.New("missing '='")
		// }
		name := strings.ToLower(vars[0])
		value := vars[1]

		switch name {
		case "email":
			user.Email = value
		case "role":
			user.Role = value
		case "uid":
			{
				num, err := strconv.Atoi(value)
				if err != nil {
					return User{}, errors.New("uid field should be an integer")
				}
				user.UID = num
			}
		default:
			return User{}, errors.New("invalid field name, only 'email', 'role', 'uid'")
		}
	}
	return user, nil
}

func profileFor(email string) ([]byte, error) {
	// Do email string validation
	// it should not contain `&` and `=`
	if strings.ContainsRune(email, rune('&')) || strings.ContainsRune(email, rune('=')) {
		return []byte{}, errors.New("invalid email")
	}

	var user User
	user.Email = email
	user.Role = "user"
	user.UID = 10

	encodedProfile := user.Encode()

	key := GlobalKey
	encryptedProfile, err := set1.EncryptAES128ECB([]byte(encodedProfile), key)
	if err != nil {
		return []byte{}, err
	}

	return encryptedProfile, nil
}

func decryptAndParse(encryptedProfile, key []byte) (string, error) {
	decryptedProfile, err := set1.DecryptAES128ECB(encryptedProfile, key)
	if err != nil {
		return "", err
	}
	// decryptedProfile = PKCS7Strip(decryptedProfile)
	parsedProfile, err := parseToUser(string(decryptedProfile))
	if err != nil {
		return "", err
	}
	return parsedProfile.String(), nil
}

func S2C13RunChallenge() error {
	key := GlobalKey
	myEmail := "nac@gmail.admin\t\t\t\t\t\t\t\t\t\t\tcom"
	encryptedProfile, err := profileFor(myEmail)
	if err != nil {
		return err
	}

	// Attacker side: ECB cut and paste
	// Intercept the ciphertext and make a role=admin profile
	// Drafted ciphertext blocks:
	// 1: email=nac@gmail.
	// 2: admin-----------
	// 3: com&uid=10&role=
	// 4: user
	// The 'admin\t\t\t\t\t\t\t\t\t\t\t' would be on the 2nd block of ciphertext

	// Replace the 4th block by the 2nd block
	copy(encryptedProfile[BlockSize*3:BlockSize*4], encryptedProfile[BlockSize:BlockSize*2])
	var newEncryptedProfile []byte
	newEncryptedProfile = append(newEncryptedProfile, encryptedProfile[:BlockSize]...)
	newEncryptedProfile = append(newEncryptedProfile, encryptedProfile[BlockSize*2:]...)

	parsedProfile, err := decryptAndParse(newEncryptedProfile, key)
	if err != nil {
		return err
	}

	fmt.Println(parsedProfile)
	return nil
}
