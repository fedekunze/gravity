package keeper

import (
	"fmt"
	"math"
	"strconv"

	"github.com/althea-net/peggy/module/x/peggy/types"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store/prefix"
	sdk "github.com/cosmos/cosmos-sdk/types"
	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tendermint/tendermint/libs/log"
)

type AttestationHandler interface {
	Handle(sdk.Context, types.Attestation, types.EthereumClaim) error
}

// Keeper maintains the link to storage and exposes getter/setter methods for the various parts of the state machine
type Keeper struct {
	StakingKeeper types.StakingKeeper

	storeKey   sdk.StoreKey // Unexposed key to access store from sdk.Context
	paramSpace paramtypes.Subspace

	cdc        codec.BinaryMarshaler // The wire codec for binary encoding/decoding.
	bankKeeper types.BankKeeper

	attestationHandler AttestationHandler
}

// NewKeeper returns a new instance of the peggy keeper
func NewKeeper(cdc codec.BinaryMarshaler, storeKey sdk.StoreKey, paramSpace paramtypes.Subspace, stakingKeeper types.StakingKeeper, bankKeeper types.BankKeeper) Keeper {
	// set KeyTable if it has not already been set
	if !paramSpace.HasKeyTable() {
		paramSpace = paramSpace.WithKeyTable(types.ParamKeyTable())
	}

	k := Keeper{
		cdc:           cdc,
		paramSpace:    paramSpace,
		storeKey:      storeKey,
		StakingKeeper: stakingKeeper,
		bankKeeper:    bankKeeper,
	}
	k.attestationHandler = DefaultAttestationHandler{
		keeper:     k,
		bankKeeper: bankKeeper,
	}

	return k
}

// Logger returns a module-specific logger.
func (k Keeper) Logger(ctx sdk.Context) log.Logger {
	return ctx.Logger().With("module", fmt.Sprintf("x/%s", types.ModuleName))
}

/////////////////////////////
//     VALSET REQUESTS     //
/////////////////////////////

// SetValsetRequest returns a new instance of the Peggy BridgeValidatorSet
// i.e. {"nonce": 1, "memebers": [{"eth_addr": "foo", "power": 11223}]}
func (k Keeper) SetValsetRequest(ctx sdk.Context) *types.Valset {
	valset := k.GetCurrentValset(ctx)
	k.StoreValset(ctx, valset)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeMultisigUpdateRequest,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
			sdk.NewAttribute(types.AttributeKeyContract, k.GetBridgeContractAddress(ctx)),
			sdk.NewAttribute(types.AttributeKeyBridgeChainID, strconv.Itoa(int(k.GetBridgeChainID(ctx)))),
			sdk.NewAttribute(types.AttributeKeyMultisigID, fmt.Sprint(valset.Nonce)),
			sdk.NewAttribute(types.AttributeKeyNonce, fmt.Sprint(valset.Nonce)),
		),
	)

	return valset
}

// StoreValset is for storing a validator set at a given height
func (k Keeper) StoreValset(ctx sdk.Context, valset *types.Valset) {
	store := ctx.KVStore(k.storeKey)
	valset.Height = uint64(ctx.BlockHeight())
	store.Set(types.GetValsetKey(valset.Nonce), k.cdc.MustMarshalBinaryBare(valset))
}

// StoreValsetUnsafe is for storing a validator set at a given height
func (k Keeper) StoreValsetUnsafe(ctx sdk.Context, valset *types.Valset) {
	store := ctx.KVStore(k.storeKey)
	store.Set(types.GetValsetKey(valset.Nonce), k.cdc.MustMarshalBinaryBare(valset))
}

// HasValsetRequest returns true if a valset defined by a nonce exists
func (k Keeper) HasValsetRequest(ctx sdk.Context, nonce uint64) bool {
	store := ctx.KVStore(k.storeKey)
	return store.Has(types.GetValsetKey(nonce))
}

// DeleteValset deletes the valset at a given nonce from state
func (k Keeper) DeleteValset(ctx sdk.Context, nonce uint64) {
	ctx.KVStore(k.storeKey).Delete(types.GetValsetKey(nonce))
}

// GetValset returns a valset by nonce
func (k Keeper) GetValset(ctx sdk.Context, nonce uint64) (types.Valset, bool) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.GetValsetKey(nonce))
	if bz == nil {
		return types.Valset{}, false
	}

	var valset types.Valset
	k.cdc.MustUnmarshalBinaryBare(bz, &valset)
	return valset, true
}

// IterateValsets retruns all valsetRequests
func (k Keeper) IterateValsets(ctx sdk.Context, cb func(key []byte, val *types.Valset) bool) {
	prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), types.ValsetRequestKey)
	iter := prefixStore.ReverseIterator(nil, nil)

	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var valset types.Valset
		k.cdc.MustUnmarshalBinaryBare(iter.Value(), &valset)

		if cb(iter.Key(), &valset) {
			break // stop
		}
	}
}

// GetValsets returns all the validator sets in state
func (k Keeper) GetValsets(ctx sdk.Context) types.Valsets {
	valsets := make(types.Valsets, 0)

	k.IterateValsets(ctx, func(_ []byte, val *types.Valset) bool {
		valsets = append(valsets, val)
		return false
	})

	return valsets
}

/////////////////////////////
//     VALSET CONFIRMS     //
/////////////////////////////

// GetValsetConfirm returns a valset confirmation by a nonce and validator address
func (k Keeper) GetValsetConfirm(ctx sdk.Context, nonce uint64, validator sdk.AccAddress) (types.MsgValsetConfirm, bool) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.GetValsetConfirmKey(nonce, validator))
	if bz == nil {
		return types.MsgValsetConfirm{}, false
	}

	confirm := types.MsgValsetConfirm{}
	k.cdc.MustUnmarshalBinaryBare(bz, &confirm)
	return confirm, true
}

// SetValsetConfirm sets a valset confirmation
func (k Keeper) SetValsetConfirm(ctx sdk.Context, valsetConf types.MsgValsetConfirm) []byte {
	store := ctx.KVStore(k.storeKey)
	addr, err := sdk.AccAddressFromBech32(valsetConf.Orchestrator)
	if err != nil {
		panic(err)
	}

	key := types.GetValsetConfirmKey(valsetConf.Nonce, addr)
	store.Set(key, k.cdc.MustMarshalBinaryBare(&valsetConf))
	return key
}

// GetValsetConfirms returns all validator set confirmations by nonce
func (k Keeper) GetValsetConfirms(ctx sdk.Context, nonce uint64) (confirms []*types.MsgValsetConfirm) {
	prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), types.ValsetConfirmKey)
	start, end := prefixRange(types.UInt64Bytes(nonce))
	iterator := prefixStore.Iterator(start, end)

	defer iterator.Close()

	for ; iterator.Valid(); iterator.Next() {
		confirm := types.MsgValsetConfirm{}
		k.cdc.MustUnmarshalBinaryBare(iterator.Value(), &confirm)
		confirms = append(confirms, &confirm)
	}

	return confirms
}

// IterateValsetConfirmByNonce iterates through all valset confirms by nonce in ASC order
// MARK finish-batches: this is where the key is iterated in the old (presumed working) code
// TODO: specify which nonce this is
func (k Keeper) IterateValsetConfirmByNonce(ctx sdk.Context, nonce uint64, cb func([]byte, types.MsgValsetConfirm) bool) {
	prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), types.ValsetConfirmKey)
	iter := prefixStore.Iterator(prefixRange(types.UInt64Bytes(nonce)))
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		confirm := types.MsgValsetConfirm{}
		k.cdc.MustUnmarshalBinaryBare(iter.Value(), &confirm)

		if cb(iter.Key(), confirm) {
			break
		}
	}
}

/////////////////////////////
//      BATCH CONFIRMS     //
/////////////////////////////

// GetBatchConfirm returns a batch confirmation given its nonce, the token contract, and a validator address
func (k Keeper) GetBatchConfirm(ctx sdk.Context, nonce uint64, tokenContract string, validator sdk.AccAddress) (types.MsgConfirmBatch, bool) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.GetBatchConfirmKey(tokenContract, nonce, validator))
	if bz == nil {
		return types.MsgConfirmBatch{}, false
	}
	confirm := types.MsgConfirmBatch{}
	k.cdc.MustUnmarshalBinaryBare(bz, &confirm)
	return confirm, true
}

// SetBatchConfirm sets a batch confirmation by a validator
func (k Keeper) SetBatchConfirm(ctx sdk.Context, batch *types.MsgConfirmBatch) []byte {
	store := ctx.KVStore(k.storeKey)
	acc, err := sdk.AccAddressFromBech32(batch.Orchestrator)
	if err != nil {
		panic(err)
	}
	key := types.GetBatchConfirmKey(batch.TokenContract, batch.Nonce, acc)
	store.Set(key, k.cdc.MustMarshalBinaryBare(batch))
	return key
}

// IterateBatchConfirmByNonceAndTokenContract iterates through all batch confirmations
// MARK finish-batches: this is where the key is iterated in the old (presumed working) code
// TODO: specify which nonce this is
func (k Keeper) IterateBatchConfirmByNonceAndTokenContract(ctx sdk.Context, nonce uint64, tokenContract string, cb func([]byte, types.MsgConfirmBatch) bool) {
	prefixStore := prefix.NewStore(ctx.KVStore(k.storeKey), types.BatchConfirmKey)
	prefix := append([]byte(tokenContract), types.UInt64Bytes(nonce)...)
	iter := prefixStore.Iterator(prefixRange(prefix))
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		confirm := types.MsgConfirmBatch{}
		k.cdc.MustUnmarshalBinaryBare(iter.Value(), &confirm)

		if cb(iter.Key(), confirm) {
			break
		}
	}
}

// GetBatchConfirmByNonceAndTokenContract returns the batch confirms
func (k Keeper) GetBatchConfirmByNonceAndTokenContract(ctx sdk.Context, nonce uint64, tokenContract string) (out []types.MsgConfirmBatch) {
	k.IterateBatchConfirmByNonceAndTokenContract(ctx, nonce, tokenContract, func(_ []byte, msg types.MsgConfirmBatch) bool {
		out = append(out, msg)
		return false
	})
	return
}

/////////////////////////////
//       ETH ADDRESS       //
/////////////////////////////

// SetEthAddress sets the ethereum address for a given validator
func (k Keeper) SetEthAddress(ctx sdk.Context, validatorAddress sdk.ValAddress, ethAddress common.Address) {
	store := ctx.KVStore(k.storeKey)
	store.Set(types.GetEthAddressKey(validatorAddress), ethAddress.Bytes())
}

// GetEthAddress returns the eth address for a given peggy validator
func (k Keeper) GetEthAddress(ctx sdk.Context, validator sdk.ValAddress) (common.Address, bool) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.GetEthAddressKey(validator))
	if bz == nil {
		return common.Address{}, false
	}

	address := common.BytesToAddress(bz)

	return address, true
}

// GetCurrentValset gets powers from the store and normalizes them
// into an integer percentage with a resolution of uint32 Max meaning
// a given validators 'Peggy power' is computed as
// Cosmos power / total cosmos power = x / uint32 Max
// where x is the voting power on the Peggy contract. This allows us
// to only use integer division which produces a known rounding error
// from truncation equal to the ratio of the validators
// Cosmos power / total cosmos power ratio, leaving us at uint32 Max - 1
// total voting power. This is an acceptable rounding error since floating
// point may cause consensus problems if different floating point unit
// implementations are involved.
func (k Keeper) GetCurrentValset(ctx sdk.Context) *types.Valset {
	bridgeValidators := make([]*types.BridgeValidator, 0)
	var totalPower uint64

	k.StakingKeeper.IterateBondedValidatorsByPower(ctx, func(i int64, validator stakingtypes.ValidatorI) bool {
		power := uint64(validator.GetConsensusPower())

		totalPower += power

		bridgeVal := types.BridgeValidator{
			Power: power,
		}

		ethAddress, found := k.GetEthAddress(ctx, validator.GetOperator())
		if found {
			bridgeVal.EthereumAddress = ethAddress.String()
		}

		return false
	})

	// normalize power values
	for _, bridgeValidator := range bridgeValidators {
		bridgeValidator.Power = sdk.NewUint(bridgeValidator.Power).MulUint64(math.MaxUint32).QuoUint64(totalPower).Uint64()
	}

	// TODO: make the nonce an incrementing one (i.e. fetch last nonce from state, increment, set here)
	return types.NewValset(uint64(ctx.BlockHeight()), uint64(ctx.BlockHeight()), bridgeValidators)
}

/////////////////////////////
//    ADDRESS DELEGATION   //
/////////////////////////////

// SetOrchestratorValidator sets the Orchestrator key for a given validator
func (k Keeper) SetOrchestratorValidator(ctx sdk.Context, val sdk.ValAddress, orch sdk.AccAddress) {
	store := ctx.KVStore(k.storeKey)
	store.Set(types.GetOrchestratorAddressKey(orch), val.Bytes())
}

// GetOrchestratorValidator returns the validator key associated with an orchestrator key
func (k Keeper) GetOrchestratorValidator(ctx sdk.Context, orch sdk.AccAddress) sdk.ValAddress {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.GetOrchestratorAddressKey(orch))
	if bz == nil {
		return nil
	}

	return sdk.ValAddress(bz)
}

func (k Keeper) UnpackAttestationClaim(att *types.Attestation) (types.EthereumClaim, error) {
	var msg types.EthereumClaim
	err := k.cdc.UnpackAny(att.Claim, &msg)
	if err != nil {
		return nil, err
	} else {
		return msg, nil
	}
}
