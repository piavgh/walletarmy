package walletarmy

import (
	"math/big"
	"time"
)

var GAS_INFO_TTL = 60 * time.Second

type GasInfo struct {
	GasPrice         float64
	BaseGasPrice     *big.Int
	MaxPriorityPrice float64
	FeePerGas        float64
	Timestamp        time.Time
}
