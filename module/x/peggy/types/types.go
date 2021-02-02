package types

import (
	"fmt"
	math "math"
	"math/big"
	"sort"
	"strings"

	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

/////////////////////////
//      BRIDGE VALIDATOR(S)         //
//////////////////////////////////////

// Validate performs stateless checks on the validator power and address
func (b *BridgeValidator) Validate() error {
	if b.Power == 0 {
		return sdkerrors.Wrap(ErrInvalidPower, "power cannot be 0")
	}
	if IsZeroAddress(b.EthereumAddress) {
		return fmt.Errorf("validator address cannot be the zero address")
	}

	return ValidateEthAddress(b.EthereumAddress)
}

// BridgeValidators is the sorted set of validator data for Ethereum bridge MultiSig set
type BridgeValidators []*BridgeValidator

// Sort sorts the validators by power
func (b BridgeValidators) Sort() {
	sort.Slice(b, func(i, j int) bool {
		if b[i].Power == b[j].Power {
			// Secondary sort on eth address in case powers are equal
			return EthAddrLessThan(b[i].EthereumAddress, b[j].EthereumAddress)
		}
		return b[i].Power > b[j].Power
	})
}

// PowerDiff returns the difference in power between two bridge validator sets
// TODO: this needs to be potentially refactored
func (b BridgeValidators) PowerDiff(c BridgeValidators) float64 {
	powers := map[string]int64{}
	var totalB int64
	// loop over b and initialize the map with their powers
	for _, bv := range b {
		powers[bv.EthereumAddress] = int64(bv.Power)
		totalB += int64(bv.Power)
	}

	// subtract c powers from powers in the map, initializing
	// uninitialized keys with negative numbers
	for _, bv := range c {
		if val, ok := powers[bv.EthereumAddress]; ok {
			powers[bv.EthereumAddress] = val - int64(bv.Power)
		} else {
			powers[bv.EthereumAddress] = -int64(bv.Power)
		}
	}

	var delta float64
	for _, v := range powers {
		// NOTE: we care about the absolute value of the changes
		delta += math.Abs(float64(v))
	}

	return math.Abs(delta / float64(totalB))
}

// TotalPower returns the total power in the bridge validator set
func (b BridgeValidators) TotalPower() (out uint64) {
	for _, v := range b {
		out += v.Power
	}
	return
}

// HasDuplicates returns true if there are duplicates in the set
func (b BridgeValidators) HasDuplicates() bool {
	m := make(map[string]struct{}, len(b))
	for i := range b {
		m[b[i].EthereumAddress] = struct{}{}
	}
	return len(m) != len(b)
}

// GetPowers returns only the power values for all members
func (b BridgeValidators) GetPowers() []uint64 {
	r := make([]uint64, len(b))
	for i := range b {
		r[i] = b[i].Power
	}
	return r
}

// ValidateBasic performs stateless checks
func (b BridgeValidators) ValidateBasic() error {
	for _, validator := range b {
		if err := validator.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// NewValset returns a new sorted valset
func NewValset(nonce, height uint64, validators BridgeValidators) *Valset {
	validators.Sort()

	return &Valset{
		Nonce:   uint64(nonce),
		Members: validators,
		Height:  height,
	}
}

// GetCheckpoint returns the checkpoint
func (v Valset) GetCheckpoint(peggyIDstring string) ([]byte, error) {
	// error case here should not occur outside of testing since the above is a constant
	contractAbi, err := abi.JSON(strings.NewReader(ValsetCheckpointABIJSON))
	if err != nil {
		return nil, err
	}

	// the contract argument is not a arbitrary length array but a fixed length 32 byte
	// array, therefore we have to utf8 encode the string (the default in this case) and
	// then copy the variable length encoded data into a fixed length array. This function
	// will panic if peggyId is too long to fit in 32 bytes
	peggyID, err := strToFixByteArray(peggyIDstring)
	if err != nil {
		panic(err)
	}

	checkpointBytes := []uint8("checkpoint")
	var checkpoint [32]uint8
	copy(checkpoint[:], checkpointBytes[:])

	memberAddresses := make([]common.Address, len(v.Members))
	convertedPowers := make([]*big.Int, len(v.Members))
	for i, m := range v.Members {
		memberAddresses[i] = common.HexToAddress(m.EthereumAddress)
		convertedPowers[i] = big.NewInt(int64(m.Power))
	}
	// the word 'checkpoint' needs to be the same as the 'name' above in the checkpointAbiJson
	// but other than that it's a constant that has no impact on the output. This is because
	// it gets encoded as a function name which we must then discard.
	bytes, packErr := contractAbi.Pack("checkpoint", peggyID, checkpoint, big.NewInt(int64(v.Nonce)), memberAddresses, convertedPowers)

	// this should never happen outside of test since any case that could crash on encoding
	// should be filtered above.
	if packErr != nil {
		panic(fmt.Sprintf("Error packing checkpoint! %s/n", packErr))
	}

	// we hash the resulting encoded bytes discarding the first 4 bytes these 4 bytes are the constant
	// method name 'checkpoint'. If you where to replace the checkpoint constant in this code you would
	// then need to adjust how many bytes you truncate off the front to get the output of abi.encode()
	hash := crypto.Keccak256Hash(bytes[4:])
	return hash.Bytes(), err
}

// Prune returns a new Valset without members that have 0 power or an empty Ethereum address.
func (v *Valset) Prune() *Valset {
	valset := &Valset{
		Nonce:   v.Nonce,
		Members: make([]*BridgeValidator, 0),
	}

	for _, validator := range v.Members {
		if err := validator.Validate(); err == nil {
			valset.Members = append(valset.Members, v.Members[i])
		}
	}

	return valset
}

// Valsets is a collection of valset
type Valsets []*Valset

func (v Valsets) Len() int {
	return len(v)
}

func (v Valsets) Less(i, j int) bool {
	return v[i].Nonce > v[j].Nonce
}

func (v Valsets) Swap(i, j int) {
	v[i], v[j] = v[j], v[i]
}
