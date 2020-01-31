/*
 * Copyright 2019 Nalej
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package manager

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/nalej/authx/pkg/token"
	pbAuthx "github.com/nalej/grpc-authx-go"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Authx", func() {
	var manager = NewAuthxMockup()

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
			err := manager.AddRole(role)
			gomega.Expect(err).To(gomega.Succeed())
		})

		ginkgo.It("should add basic credentials with correct roleID", func() {
			err := manager.AddBasicCredentials(userName, organizationID, roleID, pass)
			gomega.Expect(err).To(gomega.Succeed())
		})

		ginkgo.It("should add basic credentials with incorrect roleID", func() {
			err := manager.AddBasicCredentials(userName, organizationID, roleID+"wrong", pass)
			gomega.Expect(err).To(gomega.HaveOccurred())
		})

		ginkgo.It("should add basic credentials two times should fail", func() {
			err := manager.AddBasicCredentials(userName, organizationID, roleID, pass)
			gomega.Expect(err).To(gomega.Succeed())

			err = manager.AddBasicCredentials(userName, organizationID, roleID, pass)
			gomega.Expect(err).To(gomega.HaveOccurred())
		})

		ginkgo.AfterEach(func() {
			err := manager.Clean()
			gomega.Expect(err).To(gomega.Succeed())
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
			err := manager.AddRole(role)
			gomega.Expect(err).To(gomega.Succeed())

			role2 := &pbAuthx.Role{
				OrganizationId: organizationID,
				RoleId:         roleID2,
				Name:           "rName2",
				Primitives:     []pbAuthx.AccessPrimitive{pbAuthx.AccessPrimitive_ORG},
			}
			err = manager.AddRole(role2)

			gomega.Expect(err).To(gomega.Succeed())
			err = manager.AddBasicCredentials(userName, organizationID, roleID, pass)
			gomega.Expect(err).To(gomega.Succeed())
		})

		ginkgo.It("should login with correct password", func() {
			response, err := manager.LoginWithBasicCredentials(userName, pass)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(response).NotTo(gomega.BeNil())
		})

		ginkgo.It("should login with incorrect password", func() {
			response, err := manager.LoginWithBasicCredentials(userName, pass+"wrong")
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(response).To(gomega.BeNil())
		})

		ginkgo.It("should change to a valid roleID", func() {
			err := manager.EditUserRole(userName, roleID2)
			gomega.Expect(err).To(gomega.Succeed())
		})

		ginkgo.It("should change to a invalid roleID", func() {
			err := manager.EditUserRole(userName, roleID2+"wrong")
			gomega.Expect(err).To(gomega.HaveOccurred())
		})
		ginkgo.It("should delete credentials", func() {
			err := manager.DeleteCredentials(userName)
			gomega.Expect(err).To(gomega.Succeed())
		})
		ginkgo.It("should delete wrong credentials", func() {
			err := manager.DeleteCredentials(userName + "wrong")
			gomega.Expect(err).To(gomega.HaveOccurred())
		})

		ginkgo.It("should change password with correct incorrect username", func() {
			newPassword := pass + "New"
			err := manager.ChangePassword(userName+"wrong", newPassword)
			gomega.Expect(err).To(gomega.HaveOccurred())
		})

		ginkgo.It("should refresh token", func() {
			response, err := manager.LoginWithBasicCredentials(userName, pass)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(response).NotTo(gomega.BeNil())

			tk, jwtErr := jwt.ParseWithClaims(response.Token, &token.Claim{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(DefaultSecret), nil
			})
			gomega.Expect(jwtErr).To(gomega.Succeed())
			gomega.Expect(tk).NotTo(gomega.BeNil())

			cl, ok := tk.Claims.(*token.Claim)
			gomega.Expect(ok).To(gomega.BeTrue())
			gomega.Expect(cl).NotTo(gomega.BeNil())

			newResponse, err := manager.RefreshToken(response.Token, response.RefreshToken)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(newResponse).NotTo(gomega.BeNil())

		})

		ginkgo.It("should reject invalid refresh token", func() {
			response, err := manager.LoginWithBasicCredentials(userName, pass)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(response).NotTo(gomega.BeNil())

			tk, jwtErr := jwt.ParseWithClaims(response.Token, &token.Claim{}, func(token *jwt.Token) (interface{}, error) {
				return []byte(DefaultSecret), nil
			})
			gomega.Expect(jwtErr).To(gomega.Succeed())
			gomega.Expect(tk).NotTo(gomega.BeNil())

			cl, ok := tk.Claims.(*token.Claim)
			gomega.Expect(ok).To(gomega.BeTrue())
			gomega.Expect(cl).NotTo(gomega.BeNil())

			newResponse, err := manager.RefreshToken(response.Token, response.RefreshToken+"wrong")
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(newResponse).To(gomega.BeNil())

		})
		ginkgo.AfterEach(func() {
			err := manager.Clean()
			gomega.Expect(err).To(gomega.Succeed())
		})
	})

})
