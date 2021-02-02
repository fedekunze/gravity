package types

import (
	"fmt"
	"time"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

// DefaultParamspace defines the default auth module parameter subspace
const (
	// todo: implement oracle constants as params
	DefaultParamspace = ModuleName
	AttestationPeriod = 24 * time.Hour // TODO: value????
)

// DefaultGenesisState returns empty genesis state
// TODO: set some better defaults here
func DefaultGenesisState() *GenesisState {
	return &GenesisState{
		Params: DefaultParams(),
	}
}

// ValidateBasic validates genesis state by looping through the params and
// calling their validation functions
func (s GenesisState) ValidateBasic() error {
	if err := s.Params.ValidateBasic(); err != nil {
		return sdkerrors.Wrap(err, "params")
	}
	return nil
}

func strToFixByteArray(s string) ([32]byte, error) {
	var out [32]byte
	if len([]byte(s)) > 32 {
		return out, fmt.Errorf("string too long")
	}
	copy(out[:], s)
	return out, nil
}
