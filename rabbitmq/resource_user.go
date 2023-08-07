package rabbitmq

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"

	rabbithole "github.com/michaelklishin/rabbit-hole/v2"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type userMetaData struct {
	IsUsingPassword bool
	IsUsingHash     bool
}

func resourceUser() *schema.Resource {
	return &schema.Resource{
		Create: CreateUser,
		Update: UpdateUser,
		Read:   ReadUser,
		Delete: DeleteUser,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"password": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
			},

			"password_hash": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"hashing_algorithm": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"tags": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
		},
		CustomizeDiff: func(context context.Context, diff *schema.ResourceDiff, v interface{}) error {
			password, passwordOk := diff.GetOk("password")
			_, passwordHashOk := diff.GetOk("password_hash")
			hashingAlgorithm, hashingAlgorithmOk := diff.GetOk("hashing_algorithm")

			// Error if both are set or neither are set
			if v == nil {
				if (passwordOk && passwordHashOk) || (!passwordOk && !passwordHashOk) {
					return errors.New("either 'password' or 'password_hash' must be set, not both")
				}
				v = userMetaData{IsUsingPassword: passwordOk, IsUsingHash: passwordHashOk}
			}

			// Default hashing algorithm
			if !hashingAlgorithmOk {
				hashingAlgorithm = "rabbit_password_hashing_sha256"
				err := diff.SetNew("hashing_algorithm", hashingAlgorithm)

				if err != nil {
					return err
				}
			}

			if passwordOk {
				oldPasswordHash, _ := diff.GetChange("password_hash")

				if oldPasswordHash == "" {
					return nil
				}
				salt, err := getSaltFromHashedPassword(oldPasswordHash.(string))

				if err != nil {
					return err
				}

				newPasswordHash, err := generateHashFromPasswordAndSalt(hashingAlgorithm.(string), password.(string), salt)

				if err != nil {
					return err
				}

				if newPasswordHash == oldPasswordHash {
					return nil
				}
				err = diff.SetNewComputed("password_hash")
				if err != nil {
					return err
				}

			}

			return nil
		},
	}
}

func CreateUser(d *schema.ResourceData, meta interface{}) error {
	rmqc := meta.(*rabbithole.Client)

	name := d.Get("name").(string)

	userSettings := rabbithole.UserSettings{
		Password: d.Get("password").(string),
		Tags:     userTagsToString(d),
	}

	user, err := rmqc.GetUser(name)
	if user != nil {
		return fmt.Errorf("User with name `%s` already exists", user.Name)
	}

	log.Printf("[DEBUG] RabbitMQ: Attempting to create user %s", name)

	resp, err := rmqc.PutUser(name, userSettings)
	log.Printf("[DEBUG] RabbitMQ: user creation response: %#v", resp)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Error creating RabbitMQ user: %s", resp.Status)
	}

	d.SetId(name)

	return ReadUser(d, meta)
}

func ReadUser(d *schema.ResourceData, meta interface{}) error {
	rmqc := meta.(*rabbithole.Client)

	user, err := rmqc.GetUser(d.Id())

	if err != nil {
		return checkDeleted(d, err)
	}

	log.Printf("[DEBUG] RabbitMQ: User retrieved: %#v", user)

	d.Set("name", user.Name)
	d.Set("hashing_algorithm", user.HashingAlgorithm.String())
	d.Set("password_hash", user.PasswordHash)

	if len(user.Tags) > 0 {
		var tagList []string
		for _, v := range user.Tags {
			if v != "" {
				tagList = append(tagList, v)
			}
		}
		if len(tagList) > 0 {
			d.Set("tags", tagList)
		}
	}

	return nil
}

func UpdateUser(d *schema.ResourceData, meta interface{}) error {
	rmqc := meta.(*rabbithole.Client)

	name := d.Id()
	tags := userTagsToString(d)
	password, passwordOk := d.GetOk("password")
	passwordHash, passwordHashOk := d.GetOk("password_hash")
	hashingAlgorithm, hashingAlgorithmOk := d.GetOk("hashing_algorithm")

	var userSettings rabbithole.UserSettings

	if passwordOk {
		userSettings = rabbithole.UserSettings{
			Password: password.(string),
			Tags:     tags,
		}
	} else if passwordHashOk && hashingAlgorithmOk {
		userSettings = rabbithole.UserSettings{
			PasswordHash:     passwordHash.(string),
			HashingAlgorithm: hashingAlgorithm.(rabbithole.HashingAlgorithm),
			Tags:             tags,
		}
	}

	log.Printf("[DEBUG] RabbitMQ: Attempting to update user %s", name)

	resp, err := rmqc.PutUser(name, userSettings)
	log.Printf("[DEBUG] RabbitMQ: User update response: %#v", resp)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Error updating RabbitMQ user: %s", resp.Status)
	}

	return ReadUser(d, meta)
}

func DeleteUser(d *schema.ResourceData, meta interface{}) error {
	rmqc := meta.(*rabbithole.Client)

	name := d.Id()
	log.Printf("[DEBUG] RabbitMQ: Attempting to delete user %s", name)

	resp, err := rmqc.DeleteUser(name)
	log.Printf("[DEBUG] RabbitMQ: User delete response: %#v", resp)
	if err != nil {
		return err
	}

	if resp.StatusCode == 404 {
		// the user was automatically deleted
		return nil
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Error deleting RabbitMQ user: %s", resp.Status)
	}

	return nil
}

func userTagsToString(d *schema.ResourceData) rabbithole.UserTags {
	tagList := rabbithole.UserTags{}
	for _, v := range d.Get("tags").([]interface{}) {
		if tag, ok := v.(string); ok {
			tagList = append(tagList, tag)
		}
	}

	return tagList
}

func getSaltFromHashedPassword(hashedPassword string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(hashedPassword)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding failed: %v", err)
	}
	salt := decoded[:4]
	return salt, nil
}

func generateHashBytesFromData(hashFunctionString string, data []byte) ([]byte, error) {
	if hashFunctionString == "rabbit_password_hashing_sha256" {
		bytes := sha256.Sum256(data)
		return bytes[:], nil
	}

	if hashFunctionString == "rabbit_password_hashing_sha512" {
		bytes := sha512.Sum512(data)
		return bytes[:], nil
	}

	if hashFunctionString == "rabbit_password_hashing_md5" {
		bytes := md5.Sum(data)
		return bytes[:], nil
	}

	return nil, errors.New("Unsupported hash function")
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return salt, fmt.Errorf("random read failed: %v", err)
	}
	return salt, nil
}

func generateHashFromPasswordAndSalt(hashFunctionString string, password string, salt []byte) (string, error) {
	passwordBytes := []byte(password)
	saltedPassword := append(salt, passwordBytes...)
	hash, err := generateHashBytesFromData(hashFunctionString, saltedPassword)
	if err != nil {
		return "", err
	}
	saltedHash := append(salt, hash[:]...)
	encoded := base64.StdEncoding.EncodeToString(saltedHash)
	return encoded, nil
}

func generateSaltedHash(hashFunctionString string, password string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}
	return generateHashFromPasswordAndSalt(hashFunctionString, password, salt)
}
