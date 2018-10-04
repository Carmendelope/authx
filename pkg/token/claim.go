/*
 * Copyright (C) 2018 Nalej - All Rights Reserved
 */

package token

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"time"
)

type PersonalClaim struct {
	UserID     string    `json:"user,omitempty"`
	Primitives [] string `json:"access,omitempty"`
	RoleName   string    `json:"role,omitempty"`
}

func NewPersonalClaim(userID string, roleName string, primitives [] string) *PersonalClaim {
	return &PersonalClaim{UserID: userID, RoleName: roleName, Primitives: primitives}
}

type Claim struct {
	jwt.StandardClaims
	PersonalClaim
}

func NewClaim(personalClaim PersonalClaim, issuer string, creationTime time.Time, expirationPeriod time.Duration) *Claim {
	stdClaim := jwt.StandardClaims{
		Issuer:    issuer,
		Id:        GenerateUUID(),
		ExpiresAt: creationTime.Add(expirationPeriod).Unix(),
		NotBefore: creationTime.Unix(),
		IssuedAt:  creationTime.Unix(),
	}

	return &Claim{StandardClaims: stdClaim, PersonalClaim: personalClaim}
}

func GenerateUUID() string {
	return uuid.New().String()
}
