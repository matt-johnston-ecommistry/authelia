package validator

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/clems4ever/authelia/internal/configuration/schema"
)

var ldapProtocolPrefix = "ldap://"
var ldapsProtocolPrefix = "ldaps://"

func validateFileAuthenticationBackend(configuration *schema.FileAuthenticationBackendConfiguration, validator *schema.StructValidator) {
	if configuration.Path == "" {
		validator.Push(errors.New("Please provide a `path` for the users database in `authentication_backend`"))
	}
}

func validateDynamoAuthenticationBackend(configuration *schema.DynamoAuthenticationBackendConfiguration, validator *schema.StructValidator) {
	if configuration.TableName == "" {
		validator.Push(errors.New("Please provide a `table_name` for the users database in `authentication_backend`"))
	}
}

func validateLdapURL(ldapURL string, validator *schema.StructValidator) string {
	u, err := url.Parse(ldapURL)

	if err != nil {
		validator.Push(errors.New("Unable to parse URL to ldap server. The scheme is probably missing: ldap:// or ldaps://"))
		return ""
	}

	if !(u.Scheme == "ldap" || u.Scheme == "ldaps") {
		validator.Push(errors.New("Unknown scheme for ldap url, should be ldap:// or ldaps://"))
		return ""
	}

	if u.Scheme == "ldap" && u.Port() == "" {
		u.Host += ":389"
	} else if u.Scheme == "ldaps" && u.Port() == "" {
		u.Host += ":636"
	}

	if !u.IsAbs() {
		validator.Push(fmt.Errorf("URL to LDAP %s is still not absolute, it should be something like ldap://127.0.0.1:389", u.String()))
	}

	return u.String()
}

func validateLdapAuthenticationBackend(configuration *schema.LDAPAuthenticationBackendConfiguration, validator *schema.StructValidator) {
	if configuration.URL == "" {
		validator.Push(errors.New("Please provide a URL to the LDAP server"))
	} else {
		configuration.URL = validateLdapURL(configuration.URL, validator)
	}

	if configuration.User == "" {
		validator.Push(errors.New("Please provide a user name to connect to the LDAP server"))
	}

	if configuration.Password == "" {
		validator.Push(errors.New("Please provide a password to connect to the LDAP server"))
	}

	if configuration.BaseDN == "" {
		validator.Push(errors.New("Please provide a base DN to connect to the LDAP server"))
	}

	if configuration.UsersFilter == "" {
		configuration.UsersFilter = "(cn={0})"
	}

	if !strings.HasPrefix(configuration.UsersFilter, "(") || !strings.HasSuffix(configuration.UsersFilter, ")") {
		validator.Push(errors.New("The users filter should contain enclosing parenthesis. For instance cn={0} should be (cn={0})"))
	}

	if configuration.GroupsFilter == "" {
		configuration.GroupsFilter = "(member={dn})"
	}

	if !strings.HasPrefix(configuration.GroupsFilter, "(") || !strings.HasSuffix(configuration.GroupsFilter, ")") {
		validator.Push(errors.New("The groups filter should contain enclosing parenthesis. For instance cn={0} should be (cn={0})"))
	}

	if configuration.GroupNameAttribute == "" {
		configuration.GroupNameAttribute = "cn"
	}

	if configuration.MailAttribute == "" {
		configuration.MailAttribute = "mail"
	}
}

// ValidateAuthenticationBackend validates and update authentication backend configuration.
func ValidateAuthenticationBackend(configuration *schema.AuthenticationBackendConfiguration, validator *schema.StructValidator) {
	if configuration.Ldap == nil && configuration.File == nil && configuration.Dynamo == nil {
		validator.Push(errors.New("Please provide `ldap`, `dynamodb`, or `file` object in `authentication_backend`"))
	}

	if configuration.Ldap != nil && configuration.File != nil {
		validator.Push(errors.New("You cannot provide both `ldap` and `file` objects in `authentication_backend`"))
	}

	if configuration.Ldap != nil && configuration.Dynamo != nil {
		validator.Push(errors.New("You cannot provide both `ldap` and `dynamo` objects in `authentication_backend`"))
	}

	if configuration.File != nil && configuration.Dynamo != nil {
		validator.Push(errors.New("You cannot provide both `file` and `dynamo` objects in `authentication_backend`"))
	}

	if configuration.File != nil {
		validateFileAuthenticationBackend(configuration.File, validator)
	} else if configuration.Ldap != nil {
		validateLdapAuthenticationBackend(configuration.Ldap, validator)
	} else if configuration.Dynamo != nil {
		validateDynamoAuthenticationBackend(configuration.Dynamo, validator)
	}
}
