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

package interceptor

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/nalej/authx/pkg/token"
	"github.com/nalej/derrors"
	"github.com/nalej/grpc-utils/pkg/conversions"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// WithServerAuthxInterceptor is a gRPC option. If this option is included, the interceptor verifies that the user is
// is authorized to use the method, using the JWT token.
func WithServerAuthxInterceptor(config *Config) grpc.ServerOption {
	return grpc.UnaryInterceptor(authxInterceptor(config))
}

func authxInterceptor(config *Config) grpc.UnaryServerInterceptor {

	return func(ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		_, ok := config.Authorization.Permissions[info.FullMethod]

		if ok {
			claim, dErr := checkJWT(ctx, config)
			if dErr != nil {
				return nil, conversions.ToGRPCError(dErr)
			}
			dErr = authorize(info.FullMethod, claim, config)

			if dErr != nil {
				return nil, conversions.ToGRPCError(dErr)
			}

			values := make([]string, 0)
			values = append(values, "user_id", claim.UserID, "organization_id", claim.OrganizationID)
			for _, p := range claim.Primitives {
				values = append(values, p, "true")
			}
			newMD := metadata.Pairs(values...)
			oldMD, ok := metadata.FromIncomingContext(ctx)
			if !ok {
				return nil, derrors.NewInternalError("impossible to extract metadata")
			}
			newContext := metadata.NewIncomingContext(ctx, metadata.Join(oldMD, newMD))
			return handler(newContext, req)

		} else {
			if !config.Authorization.AllowsAll {
				return nil, conversions.ToGRPCError(
					derrors.NewUnauthenticatedError("unauthorized method").
						WithParams(info.FullMethod))
			}
		}
		log.Warn().Msg("auth metadata has not been added")
		return handler(ctx, req)
	}

}

func checkJWT(ctx context.Context, config *Config) (*token.Claim, derrors.Error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, derrors.NewInternalError("impossible to extract metadata")
	}

	authHeader, ok := md[config.Header]
	if !ok {
		return nil, derrors.NewUnauthenticatedError("token is not supplied")
	}
	t := authHeader[0]
	// validateToken function validates the token
	tk, err := jwt.ParseWithClaims(t, &token.Claim{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.Secret), nil
	})

	if err != nil {
		return nil, derrors.NewUnauthenticatedError("token is not valid", err)
	}

	return tk.Claims.(*token.Claim), nil
}

// authorize function authorizes the token received from Metadata
func authorize(method string, claim *token.Claim, config *Config) derrors.Error {
	permission, ok := config.Authorization.Permissions[method]
	if !ok {
		if config.Authorization.AllowsAll {
			return nil
		}
		return derrors.NewUnauthenticatedError("unauthorized method").WithParams(method)
	}

	valid := permission.Valid(claim.Primitives)
	if !valid {
		return derrors.NewUnauthenticatedError("unauthorized method").WithParams(method)
	}

	return nil
}
