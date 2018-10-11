/*
 * Copyright (C) 2018 Nalej - All Rights Reserved
 */

package handler

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/nalej/authx/internal/app/authx/manager"
	"github.com/nalej/authx/pkg/token"
	pbAuthx "github.com/nalej/grpc-authx-go"
	"github.com/nalej/grpc-utils/pkg/test"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

var _ = ginkgo.Describe("Applications", func() {

	// gRPC server
	var server *grpc.Server
	// grpc test listener
	var listener *bufconn.Listener
	// client
	var client pbAuthx.AuthxClient

	var mgr *manager.Authx

	ginkgo.BeforeSuite(func() {
		listener = test.GetDefaultListener()
		server = grpc.NewServer()

		mgr = manager.NewAuthxMockup()
		handler := NewAuthx(mgr)

		pbAuthx.RegisterAuthxServer(server, handler)

		test.LaunchServer(server, listener)

		conn, err := test.GetConn(*listener)
		gomega.Expect(err).Should(gomega.Succeed())
		client = pbAuthx.NewAuthxClient(conn)
	})

	ginkgo.Context("with a role", func() {
		userName := "u1"
		organizationID := "o1"
		roleID := "r1"
		pass := "MyLittlePassword"

		ginkgo.BeforeEach(func() {
			role := &pbAuthx.Role{
				OrganizationId: organizationID,
				RoleId:         roleID,
				Name:           "rName1",
				Primitives:     []pbAuthx.AccessPrimitive{pbAuthx.AccessPrimitive_ORG},
			}
			success, err := client.AddRole(context.Background(), role)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(success).NotTo(gomega.BeNil())
		})

		ginkgo.It("add basic credentials with correct roleID", func() {
			success, err := client.AddBasicCredentials(context.Background(),
				&pbAuthx.AddBasicCredentialRequest{OrganizationId: organizationID,
					RoleId:   roleID,
					Username: userName,
					Password: pass,
				})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(success).NotTo(gomega.BeNil())
		})

		ginkgo.It("add basic credentials with incorrect roleID", func() {
			success, err := client.AddBasicCredentials(context.Background(),
				&pbAuthx.AddBasicCredentialRequest{OrganizationId: organizationID,
					RoleId:   roleID + "wrong",
					Username: userName,
					Password: pass,
				})
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(success).To(gomega.BeNil())
		})

		ginkgo.It("add basic credentials two times should fail", func() {
			success, err := client.AddBasicCredentials(context.Background(),
				&pbAuthx.AddBasicCredentialRequest{OrganizationId: organizationID,
					RoleId:   roleID,
					Username: userName,
					Password: pass,
				})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(success).NotTo(gomega.BeNil())

			success, err = client.AddBasicCredentials(context.Background(),
				&pbAuthx.AddBasicCredentialRequest{OrganizationId: organizationID,
					RoleId:   roleID,
					Username: userName,
					Password: pass,
				})
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(success).To(gomega.BeNil())
		})

	})

	ginkgo.Context("with a basic credentials and two roleIDs", func() {
		userName := "u1"
		organizationID := "o1"
		roleID := "r1"
		roleID2 := "r2"
		pass := "MyLittlePassword"

		ginkgo.BeforeEach(func() {
			role := &pbAuthx.Role{
				OrganizationId: organizationID,
				RoleId:         roleID,
				Name:           "rName1",
				Primitives:     []pbAuthx.AccessPrimitive{pbAuthx.AccessPrimitive_ORG},
			}
			success, err := client.AddRole(context.Background(), role)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(success).NotTo(gomega.BeNil())

			role2 := &pbAuthx.Role{
				OrganizationId: organizationID,
				RoleId:         roleID2,
				Name:           "rName2",
				Primitives:     []pbAuthx.AccessPrimitive{pbAuthx.AccessPrimitive_ORG},
			}
			success, err = client.AddRole(context.Background(), role2)

			gomega.Expect(err).To(gomega.Succeed())

			success, err = client.AddBasicCredentials(context.Background(),
				&pbAuthx.AddBasicCredentialRequest{OrganizationId: organizationID,
					RoleId:   roleID,
					Username: userName,
					Password: pass,
				})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(success).NotTo(gomega.BeNil())
		})

		ginkgo.It("login with correct password", func() {
			response, err := client.LoginWithBasicCredentials(context.Background(),
				&pbAuthx.LoginWithBasicCredentialsRequest{Username: userName, Password: pass})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(response).NotTo(gomega.BeNil())
		})

		ginkgo.It("login with incorrect password", func() {
			response, err := client.LoginWithBasicCredentials(context.Background(),
				&pbAuthx.LoginWithBasicCredentialsRequest{Username: userName, Password: pass + "wrong"})

			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(response).To(gomega.BeNil())
		})

		ginkgo.It("change to a valid roleID", func() {
			success, err := client.EditUserRole(context.Background(),
				&pbAuthx.EditUserRoleRequest{Username: userName, NewRoleId: roleID2})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(success).NotTo(gomega.BeNil())
		})

		ginkgo.It("change to a invalid roleID", func() {
			success, err := client.EditUserRole(context.Background(),
				&pbAuthx.EditUserRoleRequest{Username: userName, NewRoleId: roleID2+"wrong"})
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(success).To(gomega.BeNil())
		})
		ginkgo.It("delete credentials", func() {
			success,err := client.DeleteCredentials(context.Background(),&pbAuthx.DeleteCredentialsRequest{Username:userName})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(success).NotTo(gomega.BeNil())
		})
		ginkgo.It("delete wrong credentials", func() {
			success,err := client.DeleteCredentials(context.Background(),&pbAuthx.DeleteCredentialsRequest{Username:userName+"wrong"})
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(success).To(gomega.BeNil())
		})

		ginkgo.It("refresh token", func() {
			response, err := client.LoginWithBasicCredentials(context.Background(),
				&pbAuthx.LoginWithBasicCredentialsRequest{Username: userName, Password: pass})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(response).NotTo(gomega.BeNil())

			tk, jwtErr := jwt.ParseWithClaims(response.Token, &token.Claim{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(manager.DefaultSecret), nil
			})
			gomega.Expect(jwtErr).To(gomega.Succeed())
			gomega.Expect(tk).NotTo(gomega.BeNil())

			cl, ok := tk.Claims.(*token.Claim)
			gomega.Expect(ok).To(gomega.BeTrue())
			gomega.Expect(cl).NotTo(gomega.BeNil())

			newResponse, err := client.RefreshToken(context.Background(),
				&pbAuthx.RefreshTokenRequest{Username:userName,
				TokenId:cl.Id,
				RefreshToken:response.RefreshToken})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(newResponse).NotTo(gomega.BeNil())

		})

		ginkgo.It("reject invalid refresh token", func() {
			response, err := client.LoginWithBasicCredentials(context.Background(),
				&pbAuthx.LoginWithBasicCredentialsRequest{Username: userName, Password: pass})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(response).NotTo(gomega.BeNil())

			tk, jwtErr := jwt.ParseWithClaims(response.Token, &token.Claim{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(manager.DefaultSecret), nil
			})
			gomega.Expect(jwtErr).To(gomega.Succeed())
			gomega.Expect(tk).NotTo(gomega.BeNil())

			cl, ok := tk.Claims.(*token.Claim)
			gomega.Expect(ok).To(gomega.BeTrue())
			gomega.Expect(cl).NotTo(gomega.BeNil())

			newResponse, err := client.RefreshToken(context.Background(),
				&pbAuthx.RefreshTokenRequest{Username:userName,
					TokenId:cl.Id,
					RefreshToken:response.RefreshToken+"wrong"})
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(newResponse).To(gomega.BeNil())

		})

	})

	ginkgo.AfterEach(func() {
		err := mgr.Clean()
		gomega.Expect(err).To(gomega.Succeed())
	})

	ginkgo.AfterSuite(func() {
		server.Stop()
		listener.Close()
	})
})
