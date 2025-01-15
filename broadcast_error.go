package walletarmy

import (
	"fmt"
	"strings"
)

type BroadcastError error

var (
	ErrInsufficientFund = BroadcastError(fmt.Errorf("insufficient fund"))
	ErrNonceIsLow       = BroadcastError(fmt.Errorf("nonce is low"))
	ErrGasLimitIsTooLow = BroadcastError(fmt.Errorf("gas limit is too low"))
	ErrTxIsKnown        = BroadcastError(fmt.Errorf("tx is known"))
)

func NewBroadcastError(err error) BroadcastError {
	if err == nil {
		return nil
	}

	if IsNonceIsLow(err) {
		return ErrNonceIsLow
	}
	if IsGasLimitIsTooLow(err) {
		return ErrGasLimitIsTooLow
	}
	if IsTxIsKnown(err) {
		return ErrTxIsKnown
	}

	return BroadcastError(err)
}

func IsTxIsKnown(err error) bool {
	return strings.Contains(err.Error(), "already known") || strings.Contains(err.Error(), "known transaction")
}

func IsGasLimitIsTooLow(err error) bool {
	hasGasTooLow := strings.Contains(err.Error(), "gas limit") && strings.Contains(err.Error(), "low")
	hasIntrinsicGasTooLow := strings.Contains(err.Error(), "intrinsic gas") && strings.Contains(err.Error(), "low")
	hasGasLimitReach := strings.Contains(err.Error(), "gas limit") && strings.Contains(err.Error(), "reach")
	return hasGasTooLow || hasIntrinsicGasTooLow || hasGasLimitReach
}

func IsNonceIsLow(err error) bool {
	hasNonceAndLow := strings.Contains(err.Error(), "nonce") && strings.Contains(err.Error(), "low")
	hasUnderprice := strings.Contains(err.Error(), "underprice")
	hasNonceAlreadyExist := strings.Contains(err.Error(), "nonce") && strings.Contains(err.Error(), "already exist")
	return hasNonceAndLow || hasUnderprice || hasNonceAlreadyExist
}
