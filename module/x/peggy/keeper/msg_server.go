package keeper

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/althea-net/peggy/module/x/peggy/types"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/ethereum/go-ethereum/common"
)

type msgServer struct {
	Keeper
}

// NewMsgServerImpl returns an implementation of the gov MsgServer interface
// for the provided Keeper.
func NewMsgServerImpl(keeper Keeper) types.MsgServer {
	return &msgServer{Keeper: keeper}
}

var _ types.MsgServer = msgServer{}

func (k msgServer) SetOrchestratorAddress(c context.Context, msg *types.MsgSetOrchestratorAddress) (*types.MsgSetOrchestratorAddressResponse, error) {

	ctx := sdk.UnwrapSDKContext(c)

	valAddress, _ := sdk.ValAddressFromBech32(msg.Validator)
	orchestrator, _ := sdk.AccAddressFromBech32(msg.Orchestrator)

	// ensure that the validator exists
	if k.Keeper.StakingKeeper.Validator(ctx, valAddress) == nil {
		return nil, sdkerrors.Wrap(stakingtypes.ErrNoValidatorFound, valAddress.String())
	}

	// TODO consider impact of maliciously setting duplicate delegate
	// addresses since no signatures from the private keys of these addresses
	// are required for this message it could be sent in a hostile way.

	// set the orchestrator address
	k.SetOrchestratorValidator(ctx, valAddress, orchestrator)

	address := common.HexToAddress(msg.EthAddress)

	// set the ethereum address
	k.Keeper.SetEthAddress(ctx, valAddress, address)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
			sdk.NewAttribute(types.AttributeKeySetOperatorAddr, msg.Orchestrator),
		),
	)

	return &types.MsgSetOrchestratorAddressResponse{}, nil

}

// ValsetConfirm handles MsgValsetConfirm
// TODO: check msgValsetConfirm to have an Orchestrator field instead of a Validator field
func (k msgServer) ValsetConfirm(c context.Context, msg *types.MsgValsetConfirm) (*types.MsgValsetConfirmResponse, error) {
	ctx := sdk.UnwrapSDKContext(c)

	valset, found := k.GetValset(ctx, msg.Nonce)
	if !found {
		return nil, sdkerrors.Wrap(types.ErrInvalid, "couldn't find valset")
	}

	peggyID := k.GetPeggyID(ctx)
	checkpoint, err := valset.GetCheckpoint(peggyID)
	if err != nil {
		return nil, err
	}

	sigBytes, err := hex.DecodeString(msg.Signature)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalid, "signature decoding")
	}

	orchestratorAddr, _ := sdk.AccAddressFromBech32(msg.Orchestrator)
	validator := k.GetOrchestratorValidator(ctx, orchestratorAddr)
	if validator == nil {
		sval := k.StakingKeeper.Validator(ctx, sdk.ValAddress(valaddr))
		if sval == nil {
			return nil, sdkerrors.Wrap(types.ErrUnknown, "validator")
		}
		validator = sval.GetOperator()
	}

	ethAddress, found := k.GetEthAddress(ctx, validator)
	if !found {
		return nil, sdkerrors.Wrap(types.ErrEmpty, "eth address")
	}

	if err = types.ValidateEthereumSignature(checkpoint, sigBytes, ethAddress); err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalid, fmt.Sprintf("signature verification failed expected sig by %s with peggy-id %s with checkpoint %s found %s", ethAddress, peggyID, hex.EncodeToString(checkpoint), msg.Signature))
	}

	// persist signature
	if k.GetValsetConfirm(ctx, msg.Nonce, valaddr) != nil {
		return nil, sdkerrors.Wrap(types.ErrDuplicate, "signature duplicate")
	}
	key := k.SetValsetConfirm(ctx, *msg)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
			sdk.NewAttribute(types.AttributeKeyValsetConfirmKey, string(key)),
		),
	)

	return &types.MsgValsetConfirmResponse{}, nil
}

// SendToEth handles MsgSendToEth
func (k msgServer) SendToEth(c context.Context, msg *types.MsgSendToEth) (*types.MsgSendToEthResponse, error) {
	ctx := sdk.UnwrapSDKContext(c)
	sender, _ := sdk.AccAddressFromBech32(msg.Sender)

	txID, err := k.AddToOutgoingPool(ctx, sender, msg.EthDest, msg.Amount, msg.BridgeFee)
	if err != nil {
		return nil, err
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
			sdk.NewAttribute(types.AttributeKeyOutgoingTXID, fmt.Sprint(txID)),
		),
	)

	return &types.MsgSendToEthResponse{}, nil
}

// RequestBatch handles MsgRequestBatch
func (k msgServer) RequestBatch(c context.Context, msg *types.MsgRequestBatch) (*types.MsgRequestBatchResponse, error) {
	ctx := sdk.UnwrapSDKContext(c)
	ec, err := types.ERC20FromPeggyCoin(sdk.NewInt64Coin(msg.Denom, 0))
	if err != nil {
		return nil, err
	}
	batchID, err := k.BuildOutgoingTXBatch(ctx, ec.Contract, OutgoingTxBatchSize)
	if err != nil {
		return nil, err
	}

	valaddr, _ := sdk.AccAddressFromBech32(msg.Orchestrator)
	validator := k.GetOrchestratorValidator(ctx, valaddr)
	if validator == nil {
		sval := k.StakingKeeper.Validator(ctx, sdk.ValAddress(valaddr))
		if sval == nil {
			return nil, sdkerrors.Wrap(types.ErrUnknown, "validator")
		}
		validator = sval.GetOperator()
	}

	// TODO later make sure that Demon matches a list of tokens already
	// in the bridge to send

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
			sdk.NewAttribute(types.AttributeKeyBatchNonce, fmt.Sprint(batchID.BatchNonce)),
		),
	)

	return &types.MsgRequestBatchResponse{}, nil
}

// ConfirmBatch handles MsgConfirmBatch
func (k msgServer) ConfirmBatch(c context.Context, msg *types.MsgConfirmBatch) (*types.MsgConfirmBatchResponse, error) {
	ctx := sdk.UnwrapSDKContext(c)

	// fetch the outgoing batch given the nonce
	batch := k.GetOutgoingTXBatch(ctx, msg.TokenContract, msg.Nonce)
	if batch == nil {
		return nil, sdkerrors.Wrap(types.ErrInvalid, "couldn't find batch")
	}

	peggyID := k.GetPeggyID(ctx)
	checkpoint, err := batch.GetCheckpoint(peggyID)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalid, "checkpoint generation")
	}

	sigBytes, err := hex.DecodeString(msg.Signature)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalid, "signature decoding")
	}

	valaddr, _ := sdk.AccAddressFromBech32(msg.Orchestrator)
	validator := k.GetOrchestratorValidator(ctx, valaddr)
	if validator == nil {
		sval := k.StakingKeeper.Validator(ctx, sdk.ValAddress(valaddr))
		if sval == nil {
			return nil, sdkerrors.Wrap(types.ErrUnknown, "validator")
		}
		validator = sval.GetOperator()
	}

	ethAddress := k.GetEthAddress(ctx, validator)
	if ethAddress == "" {
		return nil, sdkerrors.Wrap(types.ErrEmpty, "eth address")
	}

	err = types.ValidateEthereumSignature(checkpoint, sigBytes, ethAddress)
	if err != nil {
		return nil, sdkerrors.Wrap(types.ErrInvalid, fmt.Sprintf("signature verification failed expected sig by %s with peggy-id %s with checkpoint %s found %s", ethAddress, peggyID, hex.EncodeToString(checkpoint), msg.Signature))
	}

	// check if we already have this confirm
	if k.GetBatchConfirm(ctx, msg.Nonce, msg.TokenContract, valaddr) != nil {
		return nil, sdkerrors.Wrap(types.ErrDuplicate, "duplicate signature")
	}
	key := k.SetBatchConfirm(ctx, msg)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
			sdk.NewAttribute(types.AttributeKeyBatchConfirmKey, string(key)),
		),
	)

	return nil, nil
}

// DepositClaim handles MsgDepositClaim
// TODO it is possible to submit an old msgDepositClaim (old defined as covering an event nonce that has already been
// executed aka 'observed' and had it's slashing window expire) that will never be cleaned up in the endblocker. This
// should not be a security risk as 'old' events can never execute but it does store spam in the chain.
func (k msgServer) DepositClaim(c context.Context, msg *types.MsgDepositClaim) (*types.MsgDepositClaimResponse, error) {
	ctx := sdk.UnwrapSDKContext(c)

	orch, _ := sdk.AccAddressFromBech32(msg.Orchestrator)
	validator := k.GetOrchestratorValidator(ctx, orch)
	if validator == nil {
		sval := k.StakingKeeper.Validator(ctx, sdk.ValAddress(orch))
		if sval == nil {
			return nil, sdkerrors.Wrap(types.ErrUnknown, "validator")
		}
		validator = sval.GetOperator()
	}

	// return an error if the validator isn't in the active set
	val := k.StakingKeeper.Validator(ctx, validator)
	if val == nil || !val.IsBonded() {
		return nil, sdkerrors.Wrap(sdkerrors.ErrorInvalidSigner, "validator not in active set")
	}

	any, err := codectypes.NewAnyWithValue(msg)
	if err != nil {
		return nil, err
	}

	// Add the claim to the store
	_, err = k.Attest(ctx, msg, any)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "create attestation")
	}

	// Emit the handle message event
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
			// TODO: maybe return something better here? is this the right string representation?
			sdk.NewAttribute(types.AttributeKeyAttestationID, string(types.GetAttestationKey(msg.EventNonce, msg.ClaimHash()))),
		),
	)

	return &types.MsgDepositClaimResponse{}, nil
}

// WithdrawClaim handles MsgWithdrawClaim
// TODO it is possible to submit an old msgWithdrawClaim (old defined as covering an event nonce that has already been
// executed aka 'observed' and had it's slashing window expire) that will never be cleaned up in the endblocker. This
// should not be a security risk as 'old' events can never execute but it does store spam in the chain.
func (k msgServer) WithdrawClaim(c context.Context, msg *types.MsgWithdrawClaim) (*types.MsgWithdrawClaimResponse, error) {
	ctx := sdk.UnwrapSDKContext(c)

	orch, _ := sdk.AccAddressFromBech32(msg.Orchestrator)
	validator := k.GetOrchestratorValidator(ctx, orch)
	if validator == nil {
		sval := k.StakingKeeper.Validator(ctx, sdk.ValAddress(orch))
		if sval == nil {
			return nil, sdkerrors.Wrap(types.ErrUnknown, "validator")
		}
		validator = sval.GetOperator()
	}

	// return an error if the validator isn't in the active set
	val := k.StakingKeeper.Validator(ctx, validator)
	if val == nil || !val.IsBonded() {
		return nil, sdkerrors.Wrap(sdkerrors.ErrorInvalidSigner, "validator not in acitve set")
	}

	any, err := codectypes.NewAnyWithValue(msg)
	if err != nil {
		return nil, err
	}

	// Add the claim to the store
	_, err = k.Attest(ctx, msg, any)
	if err != nil {
		return nil, sdkerrors.Wrap(err, "create attestation")
	}

	// Emit the handle message event
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			sdk.EventTypeMessage,
			sdk.NewAttribute(sdk.AttributeKeyModule, types.ModuleName),
			// TODO: maybe return something better here? is this the right string representation?
			sdk.NewAttribute(types.AttributeKeyAttestationID, string(types.GetAttestationKey(msg.EventNonce, msg.ClaimHash()))),
		),
	)

	return &types.MsgWithdrawClaimResponse{}, nil
}
