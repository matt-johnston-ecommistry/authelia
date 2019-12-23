package authentication

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/clems4ever/authelia/internal/configuration/schema"
)

// FileUserProvider is a provider reading details from a file.
type DynamoUserProvider struct {
	table   *string
	session *session.Session
	conn    *dynamodb.DynamoDB
}

// DynamoDetailsModel is the model of user details in the file database.
type DynamoUserDetailsModel struct {
	Username       string   `dynamodbav:"username" valid:"required"`
	HashedPassword string   `dynamodbav:"password" valid:"required"`
	Email          string   `dynamodbav:"email"`
	Groups         []string `dynamodbav:"groups"`
}

// NewFileUserProvider creates a new instance of FileUserProvider.
func NewDynamoUserProvider(cfg *schema.DynamoAuthenticationBackendConfiguration) *DynamoUserProvider {
	provider := DynamoUserProvider{
		table: &cfg.TableName,
	}

	opts := session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}
	if cfg.AwsProfile != "" {
		opts.Profile = cfg.AwsProfile
	}

	provider.session = session.Must(session.NewSessionWithOptions(opts))
	provider.conn = dynamodb.New(provider.session)

	return &provider
}

func (p *DynamoUserProvider) dynamoGetUser(username string, consistent bool) (*DynamoUserDetailsModel, error) {
	out, err := p.conn.GetItem(&dynamodb.GetItemInput{
		TableName: p.table,
		Key: map[string]*dynamodb.AttributeValue{
			"username": {
				S: &username,
			},
		},
		ConsistentRead: &consistent,
	})
	if err != nil {
		return nil, errors.New("Failed to get user record from DynamoDB")
	}
	details := DynamoUserDetailsModel{}
	err = dynamodbattribute.UnmarshalMap(out.Item, &details)
	if err != nil {
		return nil, err
	}
	if details.Username != username {
		return nil, errors.New("Invalid user entry retrieved from DynamoDB, or user does not exist")
	}
	return &details, nil
}

func (p *DynamoUserProvider) dynamoPutUser(user *DynamoUserDetailsModel) error {
	itm, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return err
	}
	_, err = p.conn.PutItem(&dynamodb.PutItemInput{
		TableName: p.table,
		Item:      itm,
	})
	return err
}

// CheckUserPassword checks if provided password matches for the given user.
func (p *DynamoUserProvider) CheckUserPassword(username string, password string) (bool, error) {
	user, err := p.dynamoGetUser(username, true)
	if err != nil {
		return false, err
	}
	hashedPassword := user.HashedPassword[7:] // Remove {CRYPT}
	ok, err := CheckPassword(password, hashedPassword)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// GetDetails retrieve the groups a user belongs to.
func (p *DynamoUserProvider) GetDetails(username string) (*UserDetails, error) {
	user, err := p.dynamoGetUser(username, true)
	if err != nil {
		return nil, err
	}
	return &UserDetails{
		Emails: []string{user.Email},
		Groups: user.Groups,
	}, nil
}

// UpdatePassword update the password of the given user.
func (p *DynamoUserProvider) UpdatePassword(username string, newPassword string) error {
	user, err := p.dynamoGetUser(username, true)
	if err != nil {
		return err
	}

	hash := HashPassword(newPassword, "")
	user.HashedPassword = fmt.Sprintf("{CRYPT}%s", hash)

	return p.dynamoPutUser(user)
}
