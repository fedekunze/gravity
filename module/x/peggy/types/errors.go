package types

import (
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	// ErrInvalidNonce is an SDK error when the provided nonce is invalid
	ErrInvalidNonce = sdkerrors.Register(ModuleName, 2, "invalid nonce")
	// ErrInvalidSignature is an SDK error when the provided nonce is invalid
	ErrInvalidSignature = sdkerrors.Register(ModuleName, 3, "invalid signature")
	// ErrInvalidPower is an SDK error when the provided nonce is invalid
	ErrInvalidPower = sdkerrors.Register(ModuleName, 3, "invalid eth validator power")
)
