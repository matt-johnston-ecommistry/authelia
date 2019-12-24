package validator

import (
	"errors"

	"github.com/clems4ever/authelia/internal/configuration/schema"
)

// ValidateSQLStorage validates storage configuration.
func ValidateSQLStorage(configuration *schema.StorageConfiguration, validator *schema.StructValidator) {
	if configuration.Local == nil && configuration.MySQL == nil && configuration.PostgreSQL == nil && configuration.Dynamo == nil {
		validator.Push(errors.New("A storage configuration must be provided. It could be 'local', 'mysql', 'dynamo', or 'postgres'"))
	}

	if configuration.MySQL != nil {
		validateSQLConfiguration(&configuration.MySQL.SQLStorageConfiguration, validator)
	} else if configuration.PostgreSQL != nil {
		validatePostgreSQLConfiguration(configuration.PostgreSQL, validator)
	} else if configuration.Dynamo != nil {
		validateDynamoConfiguration(configuration.Dynamo, validator)
	} else if configuration.Local != nil {
		validateLocalStorageConfiguration(configuration.Local, validator)
	}
}

func validateSQLConfiguration(configuration *schema.SQLStorageConfiguration, validator *schema.StructValidator) {
	if configuration.Password != "" && configuration.Username == "" {
		validator.Push(errors.New("Username and password must be provided"))
	}

	if configuration.Database == "" {
		validator.Push(errors.New("A database must be provided"))
	}
}

func validateDynamoConfiguration(configuration *schema.DynamoStorageConfiguration, validator *schema.StructValidator) {
	if configuration.UserTable == "" {
		validator.Push(errors.New("User Table must be provided"))
	}

	if configuration.TokenTable == "" {
		validator.Push(errors.New("Token Table must be provided"))
	}

	if configuration.AuthLogTable == "" {
		validator.Push(errors.New("Auth Log Table must be provided"))
	}
}

func validatePostgreSQLConfiguration(configuration *schema.PostgreSQLStorageConfiguration, validator *schema.StructValidator) {
	validateSQLConfiguration(&configuration.SQLStorageConfiguration, validator)

	if configuration.SSLMode == "" {
		configuration.SSLMode = "disable"
	}

	if !(configuration.SSLMode == "disable" || configuration.SSLMode == "require" ||
		configuration.SSLMode == "verify-ca" || configuration.SSLMode == "verify-full") {
		validator.Push(errors.New("SSL mode must be 'disable', 'require', 'verify-ca' or 'verify-full'"))
	}
}

func validateLocalStorageConfiguration(configuration *schema.LocalStorageConfiguration, validator *schema.StructValidator) {
	if configuration.Path == "" {
		validator.Push(errors.New("A file path must be provided with key 'path'"))
	}
}
