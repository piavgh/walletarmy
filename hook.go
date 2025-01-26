package walletarmy

import "github.com/ethereum/go-ethereum/core/types"

type Hook func(tx *types.Transaction, err error) error
