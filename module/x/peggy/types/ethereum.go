package types

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/ethereum/go-ethereum/common"
)

const (
	// PeggyDenomPrefix indicates the prefix for all assets minted by this module
	PeggyDenomPrefix = ModuleName

	// PeggyDenomSeparator is the separator for peggy denoms
	PeggyDenomSeparator = ""

	// ETHContractAddressLen is the length of contract address strings
	ETHContractAddressLen = 42
)

// EthAddrLessThan migrates the Ethereum address less than function
func EthAddrLessThan(e, o string) bool {
	return bytes.Compare([]byte(e)[:], []byte(o)[:]) == -1
}

// ValidateEthAddress validates the ethereum address strings
func ValidateEthAddress(hexAddress string) error {
	if strings.TrimSpace(hexAddress) == "" {
		return errors.New("hex address cannot be blank")
	}

	if !regexp.MustCompile("^0x[0-9a-fA-F]{40}$").MatchString(hexAddress) {
		return fmt.Errorf("address(%s) doesn't pass regex", hexAddress)
	}

	if len(hexAddress) != ETHContractAddressLen {
		return fmt.Errorf("address(%s) of the wrong length exp(%d) actual(%d)", hexAddress, len(hexAddress), ETHContractAddressLen)
	}

	return nil
}

// IsZeroAddress returns true if the given hex address corresponds to the default zero address on Ethereum.
func IsZeroAddress(hexAddress string) bool {
	if hexAddress == (common.Address{}).String() {
		return true
	}
	return false
}

/////////////////////////
//     ERC20Token      //
/////////////////////////

// NewERC20Token returns a new instance of an ERC20
func NewERC20Token(amount uint64, contractAddress string) *ERC20Token {
	return &ERC20Token{
		Amount:          sdk.NewIntFromUint64(amount),
		ContractAddress: contractAddress,
	}
}

// GetAddress returns the ethereum address of the contract
func (e ERC20Token) GetAddress() common.Address {
	return common.HexToAddress(e.ContractAddress)
}

// PeggyCoin returns the peggy representation of the ERC20
func (e *ERC20Token) PeggyCoin() sdk.Coin {
	return sdk.NewCoin(fmt.Sprintf("%s%s%s", PeggyDenomPrefix, PeggyDenomSeparator, e.ContractAddress), e.Amount)
}

// Validate permforms stateless validation of the ERC20 token fields
// - contract address matches the ethereum format
// - contract address is not the zero address from ethereum
// - token amount is positive
func (e *ERC20Token) Validate() error {
	if err := ValidateEthAddress(e.ContractAddress); err != nil {
		return sdkerrors.Wrap(err, "ethereum address")
	}

	if IsZeroAddress(e.ContractAddress) {
		return fmt.Errorf("contract address cannot be the zero address")
	}

	if !e.Amount.IsPositive() {
		return fmt.Errorf("token amount must be positive: %s", e.Amount)
	}

	return nil
}

// Add adds one ERC20 to another. It returns an error if the contract addresses are
// different or if the sum is not a valid uint64 value.
func (e ERC20Token) Add(token ERC20Token) (*ERC20Token, error) {
	if string(e.ContractAddress) != string(token.ContractAddress) {
		return nil, fmt.Errorf("token contract address mismatch, expected %s, got %s", e.ContractAddress, token.ContractAddress)
	}

	sum := e.Amount.Add(token.Amount)
	if !sum.IsUint64() {
		return nil, fmt.Errorf("uint64 overflow: result %s is not a valid uint64", sum)
	}

	return NewERC20Token(sum.Uint64(), e.ContractAddress), nil
}

// ERC20FromPeggyCoin returns the ERC20 representation of a given peggy coin
func ERC20FromPeggyCoin(coin sdk.Coin) (*ERC20Token, error) {
	err := ValidateBridgeCoin(coin)
	if err != nil {
		return nil, err
	}

	prefix := PeggyDenomPrefix + PeggyDenomSeparator
	address := strings.TrimPrefix(coin.Denom, prefix)

	return &ERC20Token{
		ContractAddress: address,
		Amount:          coin.Amount,
	}, nil
}

// ValidateBridgeCoin returns check that a the coin is a valid representation of an ERC20 token.
// In particular it returns an error if:
//	- the coin is not a valid SDK coin
//	- the coin denom doesn't contain the expected prefix
//	- the coin denom doesn't contain a valid hex address
//	- the coin denom contains the Ethereum zero address
func ValidateBridgeCoin(coin sdk.Coin) error {
	if err := coin.Validate(); err != nil {
		return err
	}

	fullPrefix := PeggyDenomPrefix + PeggyDenomSeparator

	contractAddress := strings.TrimPrefix(coin.Denom, fullPrefix)
	if contractAddress == coin.Denom {
		return fmt.Errorf("coin denom '%s' does not contain prefix '%s'", coin.Denom, fullPrefix)
	}

	if IsZeroAddress(contractAddress) {
		return fmt.Errorf("contract address cannot be the zero address")
	}

	return ValidateEthAddress(contractAddress)
}
