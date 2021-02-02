package keeper

import (
	"github.com/althea-net/peggy/module/x/peggy/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
)

type AttestationHandler func(sdk.Context, types.Attestation, types.EthereumClaim) error

// DefaultAttestationHandler is the default entry point for Attestation processing.
func DefaultAttestationHandler(keeper *Keeper, bankKeeper types.BankKeeper) AttestationHandler {
	return func(ctx sdk.Context, att types.Attestation, claim types.EthereumClaim) error {
		switch claim := claim.(type) {
		case *types.MsgDepositClaim:
			token := types.ERC20Token{
				Amount:   claim.Amount,
				Contract: claim.TokenContract,
			}

			vouchers := sdk.NewCoins(token.PeggyCoin())
			if err := bankKeeper.MintCoins(ctx, types.ModuleName, vouchers); err != nil {
				return sdkerrors.Wrapf(err, "mint vouchers coins: %s", vouchers)
			}

			addr, err := sdk.AccAddressFromBech32(claim.CosmosReceiver)
			if err != nil {
				return sdkerrors.Wrap(err, "invalid reciever address")
			}

			if err = bankKeeper.SendCoinsFromModuleToAccount(ctx, types.ModuleName, addr, vouchers); err != nil {
				return sdkerrors.Wrap(err, "transfer vouchers")
			}

			return nil

		case *types.MsgWithdrawClaim:
			return keeper.OutgoingTxBatchExecuted(ctx, claim.TokenContract, claim.BatchNonce)

		default:
			return sdkerrors.Wrapf(types.ErrInvalid, "event type: %s", claim.GetType())
		}
	}
}
