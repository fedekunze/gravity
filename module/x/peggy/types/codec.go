package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

// ModuleCdc is the codec for the module
var ModuleCdc = codec.NewLegacyAmino()

// RegisterInterfaces registers the interfaces for the proto concrete
// implementations.
func RegisterInterfaces(registry types.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgValsetConfirm{},
		&MsgSendToEth{},
		&MsgRequestBatch{},
		&MsgConfirmBatch{},
		&MsgDepositClaim{},
		&MsgWithdrawClaim{},
		&MsgSetOrchestratorAddress{},
	)

	registry.RegisterInterface(
		"peggy.v1beta1.EthereumClaim",
		(*EthereumClaim)(nil),
		&MsgDepositClaim{},
		&MsgWithdrawClaim{},
	)

	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}

func UnpackAttestationClaim(cdc codec.BinaryMarshaler, att Attestation) (EthereumClaim, error) {
	var msg EthereumClaim

	if err := cdc.UnpackAny(att.Claim, &msg); err != nil {
		return nil, err
	}

	return msg, nil
}
