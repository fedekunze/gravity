package keeper

import (
	"github.com/althea-net/peggy/module/x/peggy/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis starts a chain from a genesis state
func InitGenesis(ctx sdk.Context, k Keeper, data types.GenesisState) {
	k.SetParams(ctx, *data.Params)

	for _, vs := range data.Valsets {
		k.StoreValsetUnsafe(ctx, vs)
	}

	// reset valset confirmations in state
	for _, conf := range data.ValsetConfirms {
		k.SetValsetConfirm(ctx, *conf)
	}

	// reset batches in state
	for _, batch := range data.Batches {
		k.StoreBatchUnsafe(ctx, batch)
	}

	// reset batch confirmations in state
	for _, conf := range data.BatchConfirms {
		k.SetBatchConfirm(ctx, &conf)
	}

	// reset attestations in state
	for _, att := range data.Attestations {
		claim, err := k.UnpackAttestationClaim(&att)
		if err != nil {
			panic("couldn't cast to claim")
		}

		k.SetAttestationUnsafe(ctx, claim.GetEventNonce(), claim.ClaimHash(), &att)
	}
}

// ExportGenesis exports all the state needed to restart the chain
// from the current state of the chain
func ExportGenesis(ctx sdk.Context, k Keeper) types.GenesisState {
	var (
		p            = k.GetParams(ctx)
		batches      = k.GetOutgoingTxBatches(ctx)
		valsets      = k.GetValsets(ctx)
		attmap       = k.GetAttestationMapping(ctx)
		vsconfs      = []*types.MsgValsetConfirm{}
		batchconfs   = []types.MsgConfirmBatch{}
		attestations = []types.Attestation{}
	)

	// export valset confirmations from state
	for _, vs := range valsets {
		vsconfs = append(vsconfs, k.GetValsetConfirms(ctx, vs.Nonce)...)
	}

	// export batch confirmations from state
	for _, batch := range batches {
		// TODO: set height = 0?
		batchconfs = append(batchconfs, k.GetBatchConfirmByNonceAndTokenContract(ctx, batch.BatchNonce, batch.TokenContract)...)
	}

	// export attestations from state
	for _, atts := range attmap {
		// TODO: set height = 0?
		attestations = append(attestations, atts...)
	}

	return types.GenesisState{
		Params:         &p,
		Valsets:        valsets,
		ValsetConfirms: vsconfs,
		Batches:        batches,
		BatchConfirms:  batchconfs,
		Attestations:   attestations,
	}
}
