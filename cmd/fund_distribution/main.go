package main

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/tranvictor/jarvis/common"
	"github.com/tranvictor/jarvis/networks"
	"github.com/tranvictor/jarvis/util"
	"github.com/tranvictor/jarvis/util/account"
	"github.com/tranvictor/walletarmy"
)

type TransferStrategyFunc func(privateKeyConfigs PrivateKeyConfigs, balances map[string]*big.Int) (initialBalances []*big.Int, targetBalances []*big.Int)

func ExecuteStrategy(network networks.Network, strategy TransferStrategyFunc, privateKeyConfigs PrivateKeyConfigs, balances map[string]*big.Int) (err error) {
	initialBalances, targetBalances := strategy(privateKeyConfigs, balances)

	transfers := findTransfers(initialBalances, targetBalances)

	fmt.Println("Transfers:")
	for _, transfer := range transfers {
		fmt.Printf("Transfer from wallet %s to wallet %s: %s wei\n", privateKeyConfigs[transfer.From].Address, privateKeyConfigs[transfer.To].Address, transfer.Amount.String())
	}

	// command the army to transfer the funds
	fmt.Println("Commanding the army to transfer the funds...")

	// make the army context and load all of the wallets
	cm := walletarmy.NewContextManager()
	for _, privateKeyConfig := range privateKeyConfigs {
		acc, err := account.NewPrivateKeyAccount(privateKeyConfig.PrivateKey)
		if err != nil {
			fmt.Printf("Error creating account from private key: %s\n", err)
			return err
		}
		cm.SetAccount(acc)
	}

	// loop through the transfers and execute them as fast as possible using the army context in parallel
	// this ensures all of the transfers are executed (transactions are mined and no transaction is dropped)

	err = ParallelExecuteTransfers(cm, initialBalances, transfers, privateKeyConfigs, network)
	fmt.Println("Transfers executed successfully")

	if err != nil {
		fmt.Printf("However %s\n", err)
	}

	// Verify the balances
	balances, err = GetBalances(network, privateKeyConfigs)
	if err != nil {
		fmt.Printf("Error getting balances: %s\n", err)
		return err
	}

	fmt.Println("Balances:")
	for _, privateKeyConfig := range privateKeyConfigs {
		fmt.Printf("Address %s: %s wei\n", privateKeyConfig.Address, balances[privateKeyConfig.Address].String())
	}

	return nil
}

func main() {
	// load all private keys from a config file
	privateKeyConfigs, err := LoadPrivateKeyConfigs("private_keys.json")
	if err != nil {
		fmt.Printf("Error loading private key configs: %s\n", err)
		return
	}

	bitfiL2 := networks.BitfiTestnet

	// get the balance of each wallet
	balances, err := GetBalances(bitfiL2, privateKeyConfigs)
	if err != nil {
		fmt.Printf("Error getting balances: %s\n", err)
		return
	}

	fmt.Println("Our walltet army contains the following wallets:")
	for i, privateKeyConfig := range privateKeyConfigs {
		fmt.Printf("Address %d: %s. ETH Balance: %s wei\n", i+1, privateKeyConfig.Address, balances[privateKeyConfig.Address].String())
	}

	// initialBalances, targetBalances := CalculateTargetBalancesForConsolidation(privateKeyConfigs, balances)
	// initialBalances, targetBalances := CalculateTargetBalancesForEvenDistribution(privateKeyConfigs, balances)

	shouldConsolidate := false
	for {
		if shouldConsolidate {
			err = ExecuteStrategy(bitfiL2, CalculateTargetBalancesForConsolidation, privateKeyConfigs, balances)
		} else {
			err = ExecuteStrategy(bitfiL2, CalculateTargetBalancesForEvenDistribution, privateKeyConfigs, balances)
		}
		if err != nil {
			fmt.Printf("Error executing strategy: %s\n", err)
			return
		}
		shouldConsolidate = !shouldConsolidate
	}
}

func ParallelExecuteTransfers(cm *walletarmy.ContextManager, initialBalances []*big.Int, transfers []Transfer, privateKeyConfigs PrivateKeyConfigs, network networks.Network) error {
	wg := sync.WaitGroup{}

	errChan := make(chan error, len(transfers))

	for _, transfer := range transfers {
		wg.Add(1)
		go func(transfer Transfer) {
			defer wg.Done()
			err := EnsureTransfer(
				cm,
				privateKeyConfigs[transfer.From],
				privateKeyConfigs[transfer.To],
				initialBalances[transfer.From],
				transfer.Amount,
				network,
			)
			if err != nil {
				err = fmt.Errorf(
					"error executing transfer from %s to %s with amount %s: %s",
					privateKeyConfigs[transfer.From].Address,
					privateKeyConfigs[transfer.To].Address,
					transfer.Amount.String(),
					err,
				)
				errChan <- err
			}
		}(transfer)
	}

	wg.Wait()
	close(errChan)

	errors := []error{}
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		errMsg := ""
		for _, err := range errors {
			errMsg += fmt.Sprintf("%s\n", err)
		}
		return fmt.Errorf("%s", errMsg)
	}

	return nil
}

// EnsureTransfer ensures that the transfer is executed and the transaction is mined, it is supposed to retry until the transfer is successful
func EnsureTransfer(cm *walletarmy.ContextManager, fromPrivateKeyConfig PrivateKeyConfig, toPrivateKeyConfig PrivateKeyConfig, initialBalance *big.Int, amount *big.Int, network networks.Network) error {
	var oldTxs map[string]*types.Transaction = map[string]*types.Transaction{}
	var tx *types.Transaction
	var err error
	var retryNonce *big.Int
	var retryGasPrice float64
	var retryTipCap float64
	// retry loop for at max 10 times
	for i := 0; i < 10; i++ {
		if initialBalance.Cmp(amount) <= 0 {
			// send all of the funds to the to address
			tx, err = cm.BuildSendAllNativeTx(
				common.HexToAddress(fromPrivateKeyConfig.Address),
				common.HexToAddress(toPrivateKeyConfig.Address),
				retryNonce,
				retryGasPrice,
				retryTipCap,
				network,
			)
		} else {
			tx, err = cm.BuildTx(
				types.DynamicFeeTxType,                            // tx type
				common.HexToAddress(fromPrivateKeyConfig.Address), // from address
				common.HexToAddress(toPrivateKeyConfig.Address),   // to address
				retryNonce,    // nonce (if nil means context manager will determine the nonce)
				amount,        // amount
				0,             // gas limit
				retryGasPrice, // gas price
				retryTipCap,   // tip cap
				nil,           // data
				network,       // network
			)
		}

		if err != nil {
			return fmt.Errorf("error building transaction: %s", err)
		}

		signexTx, successful, broadcastErr := cm.SignTxAndBroadcast(common.HexToAddress(fromPrivateKeyConfig.Address), tx, network)

		if signexTx != nil {
			oldTxs[signexTx.Hash().Hex()] = signexTx
		}

		if !successful {
			fmt.Printf(
				"Error signing and broadcasting transaction %s - Nonce: %d, Gas Price: %s, Tip Cap: %s, Max Fee Per Gas: %s   - Error: %s\n",
				signexTx.Hash().Hex(),
				tx.Nonce(),
				tx.GasPrice().String(),
				tx.GasTipCap().String(),
				tx.GasFeeCap().String(),
				broadcastErr,
			)

			// there are a few cases we should handle
			// 1. insufficient fund
			if broadcastErr == walletarmy.ErrInsufficientFund {
				// wait for 5 seconds and retry with the same nonce because the nonce is already acquired from
				// the context manager
				retryNonce = big.NewInt(int64(tx.Nonce()))
				time.Sleep(5 * time.Second)
				continue
			}

			// 2. nonce is low
			if broadcastErr == walletarmy.ErrNonceIsLow {
				// in this case, we need to check if the last transaction is mined or it is lost
				statuses, err := GetTxStatuses(cm, oldTxs, network)
				if err != nil {
					fmt.Printf("Error getting tx statuses in case where tx wasn't broadcasted because nonce is too low: %s. Ignore and continue the retry loop\n", err)
					// ignore the error and retry
					time.Sleep(5 * time.Second)
					continue
				}
				// if it is mined, we don't need to do anything, just stop the loop and return
				oldTxMined := false
				for _, status := range statuses {
					if status.Status == "done" || status.Status == "reverted" {
						oldTxMined = true
						break
					}
				}
				if oldTxMined {
					return nil
				}

				// in this case, old txes weren't mined but the nonce is already used, it means
				// a different tx is with the same nonce was mined somewhere else
				// so we need to retry with a new nonce
				retryNonce = nil
				time.Sleep(5 * time.Second)
				continue
			}

			// 3. gas limit is too low
			if broadcastErr == walletarmy.ErrGasLimitIsTooLow {
				// in this case, we just rely on the loop to hope it will finally have a better gas limit estimation
				// however, the same nonce must be used since it is acquired from the context manager already
				retryNonce = big.NewInt(int64(tx.Nonce()))
				time.Sleep(5 * time.Second)
				continue
			}

			// 4. tx is known
			if broadcastErr == walletarmy.ErrTxIsKnown {
				// in this case, we need to speed up the tx by increasing the gas price and tip cap
				// however, it should be handled by the slow status gotten from the monitor tx below
				// so we just need to retry with the same nonce
				retryNonce = big.NewInt(int64(tx.Nonce()))
				time.Sleep(5 * time.Second)
				continue
			}

			retryNonce = big.NewInt(int64(tx.Nonce()))
			time.Sleep(5 * time.Second)
			continue
		} else {
			fmt.Printf(
				"Signed and broadcasted transaction %s - Nonce: %d, Gas Price: %s, Tip Cap: %s, Max Fee Per Gas: %s\n",
				signexTx.Hash().Hex(),
				tx.Nonce(),
				tx.GasPrice().String(),
				tx.GasTipCap().String(),
				tx.GasFeeCap().String(),
			)
		}

		statusChan := cm.MonitorTx(signexTx, network)
		status := <-statusChan
		switch status {
		case "mined":
			return nil
		case "reverted":
			fmt.Printf("Transaction %s reverted, retrying...\n", signexTx.Hash().Hex())
			retryNonce = nil
			time.Sleep(5 * time.Second)
		case "lost":
			fmt.Printf("Transaction %s lost, retrying...\n", signexTx.Hash().Hex())
			retryNonce = nil
			time.Sleep(5 * time.Second)
		case "slow":
			fmt.Printf("Transaction %s slow, retrying with the same nonce and increasing gas price by 20%% and tip cap by 10%%...\n", signexTx.Hash().Hex())
			retryGasPrice = common.BigToFloat(tx.GasPrice(), 9) * 1.2
			retryTipCap = common.BigToFloat(tx.GasTipCap(), 9) * 1.1
			retryNonce = big.NewInt(int64(tx.Nonce()))
			time.Sleep(5 * time.Second)
		}
	}

	return nil
}

func GetTxStatuses(cm *walletarmy.ContextManager, oldTxs map[string]*types.Transaction, network networks.Network) ([]common.TxInfo, error) {
	result := []common.TxInfo{}

	for _, tx := range oldTxs {
		txInfo, _ := cm.Reader(network).TxInfoFromHash(tx.Hash().Hex())
		result = append(result, txInfo)
	}

	return result, nil
}

// CalculateTargetBalancesForConsolidation calculates the target balances to send all of the funds to the first wallet
func CalculateTargetBalancesForConsolidation(privateKeyConfigs PrivateKeyConfigs, balances map[string]*big.Int) ([]*big.Int, []*big.Int) {
	totalBalance := big.NewInt(0)
	for _, balance := range balances {
		totalBalance.Add(totalBalance, balance)
	}

	initialBalances := make([]*big.Int, len(privateKeyConfigs))
	targetBalances := make([]*big.Int, len(privateKeyConfigs))
	for i, privateKeyConfig := range privateKeyConfigs {
		initialBalances[i] = balances[privateKeyConfig.Address]
		targetBalances[i] = big.NewInt(0)
	}
	targetBalances[0] = totalBalance

	return initialBalances, targetBalances
}

func CalculateTargetBalancesForEvenDistribution(privateKeyConfigs PrivateKeyConfigs, balances map[string]*big.Int) ([]*big.Int, []*big.Int) {
	totalBalance := big.NewInt(0)
	for _, balance := range balances {
		totalBalance.Add(totalBalance, balance)
	}

	amountPerWallet := big.NewInt(0).Div(totalBalance, big.NewInt(int64(len(privateKeyConfigs))))

	initialBalances := make([]*big.Int, len(privateKeyConfigs))
	targetBalances := make([]*big.Int, len(privateKeyConfigs))
	for i, privateKeyConfig := range privateKeyConfigs {
		initialBalances[i] = balances[privateKeyConfig.Address]
		targetBalances[i] = big.NewInt(0).Set(amountPerWallet)
	}

	return initialBalances, targetBalances
}

func GetBalances(bitfiL2 networks.Network, privateKeyConfigs PrivateKeyConfigs) (map[string]*big.Int, error) {
	result := make(map[string]*big.Int)

	reader, err := util.EthReader(bitfiL2)
	if err != nil {
		return nil, err
	}

	for _, privateKeyConfig := range privateKeyConfigs {
		balance, err := reader.GetBalance(privateKeyConfig.Address)
		if err != nil {
			return nil, err
		}
		result[privateKeyConfig.Address] = balance
	}

	return result, nil
}
