package keeper

import (
	"context"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/althea-net/peggy/module/x/peggy/types"
	"github.com/cosmos/cosmos-sdk/store/prefix"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
)

var _ types.QueryServer = Keeper{}

// Params queries the params of the peggy module
func (k Keeper) Params(c context.Context, _ *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	params := k.GetParams(sdk.UnwrapSDKContext(c))

	return &types.QueryParamsResponse{
		Params: params,
	}, nil

}

// CurrentValset queries the CurrentValset of the peggy module
func (k Keeper) CurrentValset(c context.Context, _ *types.QueryCurrentValsetRequest) (*types.QueryCurrentValsetResponse, error) {
	return &types.QueryCurrentValsetResponse{
		Valset: k.GetCurrentValset(sdk.UnwrapSDKContext(c)),
	}, nil
}

// ValsetRequest queries the ValsetRequest of the peggy module
func (k Keeper) ValsetRequest(c context.Context, req *types.QueryValsetRequestRequest) (*types.QueryValsetRequestResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(c)
	valset, found := k.GetValset(ctx, req.Nonce)
	if !found {
		return nil, status.Errorf(codes.NotFound, "validator set at nonce %d", req.Nonce)
	}

	return &types.QueryValsetRequestResponse{
		Valset: valset,
	}, nil
}

// ValsetConfirm queries the ValsetConfirm of the peggy module
func (k Keeper) ValsetConfirm(c context.Context, req *types.QueryValsetConfirmRequest) (*types.QueryValsetConfirmResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	addr, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	valSetConfirm, found := k.GetValsetConfirm(sdk.UnwrapSDKContext(c), req.Nonce, addr)
	if !found {
		return nil, status.Errorf(codes.NotFound, "validator set confirmation by address %s at nonce %d", req.Address, req.Nonce)
	}

	return &types.QueryValsetConfirmResponse{
		Confirm: valSetConfirm,
	}, nil
}

// ValsetConfirmsByNonce queries the ValsetConfirmsByNonce of the peggy module
func (k Keeper) ValsetConfirmsByNonce(c context.Context, req *types.QueryValsetConfirmsByNonceRequest) (*types.QueryValsetConfirmsByNonceResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(c)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.ValsetConfirmKey)

	confirms := []*types.MsgValsetConfirm{}
	pageRes, err := query.Paginate(store, req.Pagination, func(_, value []byte) error {
		var valsetConfirm types.MsgValsetConfirm

		k.cdc.MustUnmarshalBinaryBare(value, &valsetConfirm)
		confirms = append(confirms, &valsetConfirm)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryValsetConfirmsByNonceResponse{
		Confirms:   confirms,
		Pagination: pageRes,
	}, nil
}

// LastValsetRequests queries the LastValsetRequests of the peggy module
func (k Keeper) LastValsetRequests(c context.Context, req *types.QueryLastValsetRequestsRequest) (*types.QueryLastValsetRequestsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(c)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.ValsetRequestKey)

	valsets := types.Valsets{}
	pageRes, err := query.Paginate(store, req.Pagination, func(_, value []byte) error {
		var valset types.Valset

		k.cdc.MustUnmarshalBinaryBare(value, &valset)
		valsets = append(valsets, &valset)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// sort before return
	sort.Sort(valsets)

	return &types.QueryLastValsetRequestsResponse{
		Valsets:    valsets,
		Pagination: pageRes,
	}, nil
}

// LastPendingValsetRequestByAddr queries the LastPendingValsetRequestByAddr of the peggy module
func (k Keeper) LastPendingValsetRequestByAddr(c context.Context, req *types.QueryLastPendingValsetRequestByAddrRequest) (*types.QueryLastPendingValsetRequestByAddrResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	addr, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, sdkerrors.Wrap(sdkerrors.ErrInvalidRequest, "address invalid")
	}

	ctx := sdk.UnwrapSDKContext(c)

	var pendingValsetReq *types.Valset
	k.IterateValsets(ctx, func(_ []byte, val *types.Valset) bool {
		// foundConfirm is true if the operatorAddr has signed the valset we are currently looking at
		// if this valset has NOT been signed by operatorAddr, store it in pendingValsetReq
		// and exit the loop
		_, found := k.GetValsetConfirm(ctx, val.Nonce, addr)
		if !found {
			pendingValsetReq = val
			return true
		}
		// return false to continue the loop
		return false
	})

	if pendingValsetReq == nil {
		return nil, status.Errorf(codes.NotFound, "last pending validator set request for address %s", req.Address)
	}

	return &types.QueryLastPendingValsetRequestByAddrResponse{
		Valset: pendingValsetReq,
	}, nil
}

// LastPendingBatchRequestByAddr queries the LastPendingBatchRequestByAddr of the peggy module
func (k Keeper) LastPendingBatchRequestByAddr(c context.Context, req *types.QueryLastPendingBatchRequestByAddrRequest) (*types.QueryLastPendingBatchRequestByAddrResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	addr, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ctx := sdk.UnwrapSDKContext(c)

	var pendingBatchReq *types.OutgoingTxBatch
	k.IterateOutgoingTXBatches(ctx, func(_ []byte, batch *types.OutgoingTxBatch) bool {
		batchConfirmation := k.GetBatchConfirm(ctx, batch.BatchNonce, batch.TokenContract, addr)

		if batchConfirmation == nil {
			pendingBatchReq = batch
			return true
		}

		return false
	})

	if pendingBatchReq == nil {
		return nil, status.Errorf(codes.NotFound, "last pending batch request for address %s", req.Address)
	}

	return &types.QueryLastPendingBatchRequestByAddrResponse{
		Batch: pendingBatchReq,
	}, nil
}

// OutgoingTxBatches queries the OutgoingTxBatches of the peggy module
func (k Keeper) OutgoingTxBatches(c context.Context, req *types.QueryOutgoingTxBatchesRequest) (*types.QueryOutgoingTxBatchesResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	ctx := sdk.UnwrapSDKContext(c)
	store := prefix.NewStore(ctx.KVStore(k.storeKey), types.OutgoingTXBatchKey)

	batches := []*types.OutgoingTxBatch{}
	pageRes, err := query.Paginate(store, req.Pagination, func(_, value []byte) error {
		var batch types.OutgoingTxBatch

		k.cdc.MustUnmarshalBinaryBare(value, &batch)
		batches = append(batches, &batch)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryOutgoingTxBatchesResponse{
		Batches:    batches,
		Pagination: pageRes,
	}, nil
}

// BatchRequestByNonce queries the BatchRequestByNonce of the peggy module
func (k Keeper) BatchRequestByNonce(c context.Context, req *types.QueryBatchRequestByNonceRequest) (*types.QueryBatchRequestByNonceResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	if err := types.ValidateEthAddress(req.ContractAddress); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	ctx := sdk.UnwrapSDKContext(c)
	foundBatch := k.GetOutgoingTXBatch(ctx, req.ContractAddress, req.Nonce)
	if foundBatch == nil {
		return nil, status.Errorf(codes.NotFound, "outgoing tx batch request for contract %s at height %d", req.ContractAddress, req.Nonce)
	}

	return &types.QueryBatchRequestByNonceResponse{
		Batch: foundBatch,
	}, nil
}

// BatchConfirms returns the batch confirmations by nonce and token contract
func (k Keeper) BatchConfirms(c context.Context, req *types.QueryBatchConfirmsRequest) (*types.QueryBatchConfirmsResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	var confirms []*types.MsgConfirmBatch
	k.IterateBatchConfirmByNonceAndTokenContract(sdk.UnwrapSDKContext(c), req.Nonce, req.ContractAddress, func(_ []byte, c types.MsgConfirmBatch) bool {
		confirms = append(confirms, &c)
		return false
	})
	return &types.QueryBatchConfirmsResponse{Confirms: confirms}, nil
}

// LastEventNonceByAddr returns the last event nonce for the given validator address, this allows eth oracles to figure out where they left off
func (k Keeper) LastEventNonceByAddr(c context.Context, req *types.QueryLastEventNonceByAddrRequest) (*types.QueryLastEventNonceByAddrResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}

	addr, err := sdk.AccAddressFromBech32(req.Address)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ctx := sdk.UnwrapSDKContext(c)

	validator := k.GetOrchestratorValidator(ctx, addr)
	if validator == nil {
		return nil, status.Errorf(codes.NotFound, "orchestrator validator %s", addr)
	}

	lastEventNonce := k.GetLastEventNonceByValidator(ctx, validator)

	return &types.QueryLastEventNonceByAddrResponse{
		EventNonce: lastEventNonce,
	}, nil
}
