package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/clems4ever/authelia/internal/authentication"
	"github.com/clems4ever/authelia/internal/authorization"
	"github.com/clems4ever/authelia/internal/configuration"
	"github.com/clems4ever/authelia/internal/logging"
	"github.com/clems4ever/authelia/internal/middlewares"
	"github.com/clems4ever/authelia/internal/notification"
	"github.com/clems4ever/authelia/internal/regulation"
	"github.com/clems4ever/authelia/internal/server"
	"github.com/clems4ever/authelia/internal/session"
	"github.com/clems4ever/authelia/internal/storage"
	"github.com/clems4ever/authelia/internal/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var configPathFlag string

func startServer() {
	if configPathFlag == "" {
		log.Fatal(errors.New("No config file path provided"))
	}

	if os.Getenv("ENVIRONMENT") == "dev" {
		logging.Logger().Info("===> Authelia is running in development mode. <===")
	}

	config, errs := configuration.Read(configPathFlag)

	if len(errs) > 0 {
		for _, err := range errs {
			logging.Logger().Error(err)
		}
		panic(errors.New("Some errors have been reported"))
	}

	switch config.LogsLevel {
	case "info":
		logging.Logger().Info("Logging severity set to info")
		logging.SetLevel(logrus.InfoLevel)
		break
	case "debug":
		logging.Logger().Info("Logging severity set to debug")
		logging.SetLevel(logrus.DebugLevel)
		break
	case "trace":
		logging.Logger().Info("Logging severity set to trace")
		logging.SetLevel(logrus.TraceLevel)
	}

	var userProvider authentication.UserProvider

	if config.AuthenticationBackend.File != nil {
		userProvider = authentication.NewFileUserProvider(config.AuthenticationBackend.File.Path)
	} else if config.AuthenticationBackend.Ldap != nil {
		userProvider = authentication.NewLDAPUserProvider(*config.AuthenticationBackend.Ldap)
	} else if config.AuthenticationBackend.Dynamo != nil {
		userProvider = authentication.NewDynamoUserProvider(config.AuthenticationBackend.Dynamo)
	} else {
		log.Fatalf("Unrecognized authentication backend")
	}

	var storageProvider storage.Provider
	if config.Storage.PostgreSQL != nil {
		storageProvider = storage.NewPostgreSQLProvider(*config.Storage.PostgreSQL)
	} else if config.Storage.MySQL != nil {
		storageProvider = storage.NewMySQLProvider(*config.Storage.MySQL)
	} else if config.Storage.Local != nil {
		storageProvider = storage.NewSQLiteProvider(config.Storage.Local.Path)
	} else {
		log.Fatalf("Unrecognized storage backend")
	}

	var notifier notification.Notifier
	if config.Notifier.SMTP != nil {
		notifier = notification.NewSMTPNotifier(*config.Notifier.SMTP)
	} else if config.Notifier.FileSystem != nil {
		notifier = notification.NewFileNotifier(*config.Notifier.FileSystem)
	} else {
		log.Fatalf("Unrecognized notifier")
	}

	clock := utils.RealClock{}
	authorizer := authorization.NewAuthorizer(*config.AccessControl)
	sessionProvider := session.NewProvider(config.Session)
	regulator := regulation.NewRegulator(config.Regulation, storageProvider, clock)

	providers := middlewares.Providers{
		Authorizer:      authorizer,
		UserProvider:    userProvider,
		Regulator:       regulator,
		StorageProvider: storageProvider,
		Notifier:        notifier,
		SessionProvider: sessionProvider,
	}
	server.StartServer(*config, providers)
}

func main() {
	rootCmd := &cobra.Command{
		Use: "authelia",
		Run: func(cmd *cobra.Command, args []string) {
			startServer()
		},
	}

	rootCmd.Flags().StringVar(&configPathFlag, "config", "", "Configuration file")

	versionCmd := &cobra.Command{
		Use: "version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("build git tag: %s\n", BuildTag)
			fmt.Printf("build git commit: %s\n", BuildCommit)
			fmt.Printf("build time: %s\n", BuildTime)
		},
	}

	rootCmd.AddCommand(versionCmd)
	rootCmd.Execute()
}
