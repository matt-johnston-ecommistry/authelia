package storage

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/clems4ever/authelia/internal/configuration/schema"
	"strconv"
	"time"

	"github.com/clems4ever/authelia/internal/models"
)

// DynamoProvider is a storage provider persisting data in a DynamoDB database.
type DynamoProvider struct {
	user_table    *string
	tokens_table  *string
	authlog_table *string
	session       *session.Session
	conn          *dynamodb.DynamoDB
}

type DynamoUser struct {
	Username           string `dynamodbav:"username"`
	SecondFactorMethod string `dynamodbav:"second_factor_method"`
	TotpSecret         string `dynamodbav:"totp_secret"`
	U2fKeyHandle       string `dynamodbav:"u2f_key_handle"`
	U2fPublicKey       string `dynamodbav:"u2f_public_key"`
}

type DynamoToken struct {
	Token string `dynamodbav:"token"`
}

type DynamoAuthLog struct {
	Username string `dynamodbav:"username"`
	Time     int64  `dynamodbav:"time"`
	Result   bool   `dynamodbav:"result"`
}

// NewDynamoProvider creates a new instance of DynamoProvider.
func NewDynamoProvider(cfg *schema.DynamoStorageConfiguration) *DynamoProvider {
	provider := DynamoProvider{
		user_table:    &cfg.UserTable,
		tokens_table:  &cfg.TokenTable,
		authlog_table: &cfg.AuthLogTable,
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

func (p *DynamoProvider) dynamoGetUser(username string, consistent bool) (*DynamoUser, error) {
	out, err := p.conn.GetItem(&dynamodb.GetItemInput{
		TableName: p.user_table,
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
	details := DynamoUser{}
	err = dynamodbattribute.UnmarshalMap(out.Item, &details)
	if err != nil {
		return nil, err
	}
	if details.Username != username {
		return nil, errors.New("Invalid user entry retrieved from DynamoDB, or user does not exist")
	}
	return &details, nil
}

func (p *DynamoProvider) dynamoPutUser(user *DynamoUser) error {
	itm, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return err
	}
	_, err = p.conn.PutItem(&dynamodb.PutItemInput{
		TableName: p.user_table,
		Item:      itm,
	})
	return err
}

func (p *DynamoProvider) dynamoGetToken(token string, consistent bool) (*DynamoToken, error) {
	out, err := p.conn.GetItem(&dynamodb.GetItemInput{
		TableName: p.tokens_table,
		Key: map[string]*dynamodb.AttributeValue{
			"token": {
				S: &token,
			},
		},
		ConsistentRead: &consistent,
	})
	if err != nil {
		return nil, errors.New("Failed to get user record from DynamoDB")
	}
	details := DynamoToken{}
	err = dynamodbattribute.UnmarshalMap(out.Item, &details)
	if err != nil {
		return nil, err
	}
	if details.Token != token {
		return nil, errors.New("Invalid user entry retrieved from DynamoDB, or user does not exist")
	}
	return &details, nil
}

func (p *DynamoProvider) dynamoPutToken(user *DynamoToken) error {
	itm, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return err
	}
	_, err = p.conn.PutItem(&dynamodb.PutItemInput{
		TableName: p.tokens_table,
		Item:      itm,
	})
	return err
}

func (p *DynamoProvider) dynamoDeleteToken(token *DynamoToken) error {
	_, err := p.conn.DeleteItem(&dynamodb.DeleteItemInput{
		TableName: p.tokens_table,
		Key: map[string]*dynamodb.AttributeValue{
			"token": {
				S: &token.Token,
			},
		},
	})
	return err
}

func (p *DynamoProvider) dynamoPutAuthlog(user *DynamoAuthLog) error {
	itm, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		return err
	}
	_, err = p.conn.PutItem(&dynamodb.PutItemInput{
		TableName: p.authlog_table,
		Item:      itm,
	})
	return err
}

// LoadPrefered2FAMethod load the prefered method for 2FA from dynamo db.
func (p *DynamoProvider) LoadPrefered2FAMethod(username string) (string, error) {
	user, err := p.dynamoGetUser(username, true)
	if err != nil {
		return "", err
	}
	return user.SecondFactorMethod, nil
}

// SavePrefered2FAMethod save the prefered method for 2FA in dynamo db.
func (p *DynamoProvider) SavePrefered2FAMethod(username string, method string) error {
	user, err := p.dynamoGetUser(username, true)
	if err != nil {
		return err
	}
	user.SecondFactorMethod = method
	err = p.dynamoPutUser(user)
	return err
}

// FindIdentityVerificationToken look for an identity verification token in DB.
func (p *DynamoProvider) FindIdentityVerificationToken(token string) (bool, error) {
	_, err := p.dynamoGetToken(token, true)
	if err != nil {
		return false, nil
	} else {
		return true, nil
	}
}

// SaveIdentityVerificationToken save an identity verification token in DB.
func (p *DynamoProvider) SaveIdentityVerificationToken(token string) error {
	return p.dynamoPutToken(&DynamoToken{
		Token: token,
	})
}

// RemoveIdentityVerificationToken remove an identity verification token from the DB.
func (p *DynamoProvider) RemoveIdentityVerificationToken(token string) error {
	return p.dynamoDeleteToken(&DynamoToken{
		Token: token,
	})
}

// SaveTOTPSecret save a TOTP secret of a given user.
func (p *DynamoProvider) SaveTOTPSecret(username string, secret string) error {
	user, err := p.dynamoGetUser(username, true)
	if err != nil {
		return err
	}
	user.TotpSecret = secret
	return p.dynamoPutUser(user)
}

// LoadTOTPSecret load a TOTP secret given a username.
func (p *DynamoProvider) LoadTOTPSecret(username string) (string, error) {
	user, err := p.dynamoGetUser(username, true)
	if err != nil {
		return "", err
	}
	return user.TotpSecret, nil
}

// DeleteTOTPSecret delete a TOTP secret given a username.
func (p *DynamoProvider) DeleteTOTPSecret(username string) error {
	return p.SaveTOTPSecret(username, "")
}

// SaveU2FDeviceHandle save a registered U2F device registration blob.
func (p *DynamoProvider) SaveU2FDeviceHandle(username string, keyHandle []byte, publicKey []byte) error {
	user, err := p.dynamoGetUser(username, true)
	if err != nil {
		return err
	}
	user.U2fKeyHandle = base64.StdEncoding.EncodeToString(keyHandle)
	user.U2fPublicKey = base64.StdEncoding.EncodeToString(publicKey)
	return p.dynamoPutUser(user)
}

// LoadU2FDeviceHandle load a U2F device registration blob for a given username.
func (p *DynamoProvider) LoadU2FDeviceHandle(username string) ([]byte, []byte, error) {
	user, err := p.dynamoGetUser(username, true)
	if err != nil {
		return nil, nil, err
	}

	keyHandle, err := base64.StdEncoding.DecodeString(user.U2fKeyHandle)

	if err != nil {
		return nil, nil, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(user.U2fPublicKey)

	if err != nil {
		return nil, nil, err
	}

	return keyHandle, publicKey, nil
}

// AppendAuthenticationLog append a mark to the authentication log.
func (p *DynamoProvider) AppendAuthenticationLog(attempt models.AuthenticationAttempt) error {
	return p.dynamoPutAuthlog(&DynamoAuthLog{
		Username: attempt.Username,
		Time:     attempt.Time.Unix(),
		Result:   attempt.Successful,
	})
}

// LoadLatestAuthenticationLogs retrieve the latest marks from the authentication log.
func (p *DynamoProvider) LoadLatestAuthenticationLogs(username string, fromDate time.Time) ([]models.AuthenticationAttempt, error) {
	res, err := p.conn.Query(&dynamodb.QueryInput{
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":pk": {
				S: &username,
			},
			":sk": {
				N: aws.String(strconv.FormatInt(fromDate.Unix(), 10)),
			},
		},
		ConsistentRead:         aws.Bool(true),
		KeyConditionExpression: aws.String("username = :pk AND time > :sk"),
		ScanIndexForward:       aws.Bool(false),
		TableName:              p.authlog_table,
	})
	if err != nil {
		return nil, err
	}
	attempts := make([]models.AuthenticationAttempt, 0, 10)
	for _, itm := range res.Items {
		authlog := DynamoAuthLog{}
		err = dynamodbattribute.UnmarshalMap(itm, &authlog)
		if err != nil {
			return nil, err
		}
		attempt := models.AuthenticationAttempt{
			Username:   username,
			Time:       time.Unix(authlog.Time, 0),
			Successful: authlog.Result,
		}
		attempts = append(attempts, attempt)
	}
	return attempts, nil
}
