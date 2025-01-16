package walletarmy

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/tranvictor/jarvis/accounts"
	jarviscommon "github.com/tranvictor/jarvis/common"
	"github.com/tranvictor/jarvis/networks"
	"github.com/tranvictor/jarvis/txanalyzer"
	"github.com/tranvictor/jarvis/util"
	"github.com/tranvictor/jarvis/util/account"
	"github.com/tranvictor/jarvis/util/broadcaster"
	"github.com/tranvictor/jarvis/util/monitor"
	"github.com/tranvictor/jarvis/util/reader"
)

// ContextManager manages
//  1. multiple wallets and their informations in its
//     life time. It basically gives next nonce to do transaction for specific
//     wallet and specific network.
//     It queries the node to check the nonce in lazy maner, it also takes mining
//     txs into account.
//  2. multiple networks gas price. The gas price will be queried lazily prior to txs
//     and will be stored as cache for a while
//  3. txs in the context manager's life time
type ContextManager struct {
	lock sync.RWMutex

	// readers stores all reader instances for all networks that ever interacts
	// with accounts manager. ChainID of the network is used as the key.
	readers      map[uint64]*reader.EthReader
	broadcasters map[uint64]*broadcaster.Broadcaster
	analyzers    map[uint64]*txanalyzer.TxAnalyzer
	txMonitors   map[uint64]*monitor.TxMonitor
	accounts     map[common.Address]*account.Account

	// nonces map between (address, network) => last signed nonce (not mined nonces)
	pendingNonces map[common.Address]map[uint64]*big.Int
	// txs map between (address, network, nonce) => tx
	txs map[common.Address]map[uint64]map[uint64]*types.Transaction

	// gasPrices map between network => gasinfo
	gasSettings map[uint64]*GasInfo
}

func NewContextManager() *ContextManager {
	return &ContextManager{
		lock:          sync.RWMutex{},
		readers:       map[uint64]*reader.EthReader{},
		broadcasters:  map[uint64]*broadcaster.Broadcaster{},
		analyzers:     map[uint64]*txanalyzer.TxAnalyzer{},
		txMonitors:    map[uint64]*monitor.TxMonitor{},
		accounts:      map[common.Address]*account.Account{},
		pendingNonces: map[common.Address]map[uint64]*big.Int{},
		txs:           map[common.Address]map[uint64]map[uint64]*types.Transaction{},
		gasSettings:   map[uint64]*GasInfo{},
	}
}

func (cm *ContextManager) SetAccount(acc *account.Account) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	cm.accounts[acc.Address()] = acc
}

func (cm *ContextManager) UnlockAccount(addr common.Address) (*account.Account, error) {
	accDesc, err := accounts.GetAccount(addr.Hex())
	if err != nil {
		return nil, fmt.Errorf("wallet %s doesn't exist in jarvis", addr.Hex())
	}
	acc, err := accounts.UnlockAccount(accDesc)
	if err != nil {
		return nil, fmt.Errorf("unlocking wallet failed: %w", err)
	}
	cm.SetAccount(acc)
	return acc, nil
}

func (cm *ContextManager) Account(wallet common.Address) *account.Account {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	return cm.accounts[wallet]
}

func (cm *ContextManager) setTx(wallet common.Address, network networks.Network, tx *types.Transaction) {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	if cm.txs[wallet] == nil {
		cm.txs[wallet] = map[uint64]map[uint64]*types.Transaction{}
	}

	if cm.txs[wallet][network.GetChainID()] == nil {
		cm.txs[wallet][network.GetChainID()] = map[uint64]*types.Transaction{}
	}

	cm.txs[wallet][network.GetChainID()][uint64(tx.Nonce())] = tx
}

func (cm *ContextManager) getBroadcaster(network networks.Network) *broadcaster.Broadcaster {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	return cm.broadcasters[network.GetChainID()]
}

func (cm *ContextManager) Broadcaster(network networks.Network) *broadcaster.Broadcaster {
	broadcaster := cm.getBroadcaster(network)
	if broadcaster == nil {
		err := cm.initNetwork(network)
		if err != nil {
			panic(
				fmt.Errorf(
					"couldn't init reader and broadcaster for network: %s, err: %s",
					network,
					err,
				),
			)
		}
		return cm.getBroadcaster(network)
	}
	return broadcaster
}

func (cm *ContextManager) getReader(network networks.Network) *reader.EthReader {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	return cm.readers[network.GetChainID()]
}

func (cm *ContextManager) Reader(network networks.Network) *reader.EthReader {
	reader := cm.getReader(network)
	if reader == nil {
		err := cm.initNetwork(network)
		if err != nil {
			panic(
				fmt.Errorf(
					"couldn't init reader and broadcaster for network: %s, err: %s",
					network,
					err,
				),
			)
		}
		return cm.getReader(network)
	}
	return reader
}

func (cm *ContextManager) getAnalyzer(network networks.Network) *txanalyzer.TxAnalyzer {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	return cm.analyzers[network.GetChainID()]
}

func (cm *ContextManager) getTxMonitor(network networks.Network) *monitor.TxMonitor {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	return cm.txMonitors[network.GetChainID()]
}

func (cm *ContextManager) Analyzer(network networks.Network) *txanalyzer.TxAnalyzer {
	analyzer := cm.getAnalyzer(network)
	if analyzer == nil {
		err := cm.initNetwork(network)
		if err != nil {
			panic(
				fmt.Errorf(
					"couldn't init reader and broadcaster for network: %s, err: %s",
					network,
					err,
				),
			)
		}
		return cm.getAnalyzer(network)
	}
	return analyzer
}

func (cm *ContextManager) initNetwork(network networks.Network) (err error) {
	cm.lock.Lock()
	defer cm.lock.Unlock()

	reader, found := cm.readers[network.GetChainID()]
	if !found {
		reader, err = util.EthReader(network)
		if err != nil {
			return err
		}
	}
	cm.readers[network.GetChainID()] = reader

	analyzer, found := cm.analyzers[network.GetChainID()]
	if !found {
		analyzer = txanalyzer.NewGenericAnalyzer(reader, network)
		if err != nil {
			return err
		}
	}
	cm.analyzers[network.GetChainID()] = analyzer

	broadcaster, found := cm.broadcasters[network.GetChainID()]
	if !found {
		broadcaster, err = util.EthBroadcaster(network)
		if err != nil {
			return err
		}
	}
	cm.broadcasters[network.GetChainID()] = broadcaster

	txMonitor, found := cm.txMonitors[network.GetChainID()]
	if !found {
		txMonitor = monitor.NewGenericTxMonitor(reader)
	}
	cm.txMonitors[network.GetChainID()] = txMonitor

	return nil
}

func (cm *ContextManager) setPendingNonce(wallet common.Address, network networks.Network, nonce uint64) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	walletNonces := cm.pendingNonces[wallet]
	if walletNonces == nil {
		walletNonces = map[uint64]*big.Int{}
		cm.pendingNonces[wallet] = walletNonces
	}
	oldNonce := walletNonces[network.GetChainID()]
	if oldNonce != nil && oldNonce.Cmp(big.NewInt(int64(nonce))) >= 0 {
		return
	}
	walletNonces[network.GetChainID()] = big.NewInt(int64(nonce))
}

func (cm *ContextManager) pendingNonce(wallet common.Address, network networks.Network) *big.Int {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	walletPendingNonces := cm.pendingNonces[wallet]
	if walletPendingNonces == nil {
		return nil
	}
	result := walletPendingNonces[network.GetChainID()]
	if result != nil {
		// when there is a pending nonce, we add 1 to get the next nonce
		result = big.NewInt(0).Add(result, big.NewInt(1))
	}
	return result
}

//  1. get remote pending nonce
//  2. get local pending nonce
//  2. get mined nonce
//  3. if mined nonce == remote == local, all good, lets return the mined nonce
//  4. since mined nonce is always <= remote nonce, if mined nonce > local nonce,
//     this session doesn't catch up with mined txs (in case there are txs  that
//     were from other apps and they were mined), return max(mined none, remote nonce)
//     and set local nonce to max(mined none, remote nonce)
//  5. if not, means mined nonce is smaller than both remote and local pending nonce
//     5.1 if remote == local: means all pending txs are from this session, we return
//     local nonce
//     5.2 if remote > local: means there is pending txs from another app, we return
//     remote nonce in order not to mess up with the other txs, but give a warning
//     5.3 if local > remote: means txs from this session are not broadcasted to the
//     the notes, return local nonce and give warnings
func (cm *ContextManager) nonce(wallet common.Address, network networks.Network) (*big.Int, error) {

	reader := cm.Reader(network)
	minedNonce, err := reader.GetMinedNonce(wallet.Hex())
	if err != nil {
		return nil, fmt.Errorf("couldn't get mined nonce in context manager: %s", err)
	}
	// fmt.Printf("mined nonce: %d\n", minedNonce)

	remotePendingNonce, err := reader.GetPendingNonce(wallet.Hex())
	if err != nil {
		return nil, fmt.Errorf("couldn't get remote pending nonce in context manager: %s", err)
	}
	// fmt.Printf("remote pending nonce: %d\n", remotePendingNonce)

	var localPendingNonce uint64
	localPendingNonceBig := cm.pendingNonce(wallet, network)
	// fmt.Printf("local pending nonce big: %d\n", localPendingNonceBig)

	if localPendingNonceBig == nil {
		cm.setPendingNonce(wallet, network, remotePendingNonce)
		// fmt.Printf("set local pending nonce to remote pending nonce: %d\n", remotePendingNonce)
		localPendingNonce = remotePendingNonce
	} else {
		localPendingNonce = localPendingNonceBig.Uint64()
	}

	hasPendingTxsOnNodes := minedNonce < remotePendingNonce
	if !hasPendingTxsOnNodes {
		if minedNonce > remotePendingNonce {
			return nil, fmt.Errorf(
				"mined nonce is higher than pending nonce, this is abnormal data from nodes, retry again later",
			)
		}
		// in this case, minedNonce is supposed to == remotePendingNonce
		if localPendingNonce <= minedNonce {
			// in this case, minedNonce is more up to date, update localPendingNonce
			// and return minedNonce
			cm.setPendingNonce(wallet, network, minedNonce)
			// fmt.Printf("localPending nonce <= mined nonce, set local pending nonce to mined nonce: %d. RETURN\n", minedNonce)
			return big.NewInt(int64(minedNonce)), nil
		} else {
			// in this case, local is more up to date, return pending nonce
			cm.setPendingNonce(wallet, network, localPendingNonce) // update local nonce to the latest
			// fmt.Printf("localPending nonce > mined nonce, set local pending nonce to local pending nonce: %d. RETURN\n", localPendingNonce)
			return big.NewInt(int64(localPendingNonce)), nil
		}
	}

	if localPendingNonce <= minedNonce {
		// localPendingNonce <= minedNonce < remotePendingNonce
		// in this case, there are pending txs on nodes and they are
		// from other apps
		// TODO: put warnings
		// we don't have to update local pending nonce here since
		// it will be updated if the new tx is broadcasted with context manager
		cm.setPendingNonce(wallet, network, remotePendingNonce) // update local nonce to the latest
		// fmt.Printf("set local pending nonce to remote pending nonce: %d. RETURN\n", remotePendingNonce)
		return big.NewInt(int64(remotePendingNonce)), nil
	} else if localPendingNonce <= remotePendingNonce {
		// minedNonce < localPendingNonce <= remotePendingNonce
		// similar to the previous case, however, there are pending txs came from
		// jarvis as well. No need special treatments
		cm.setPendingNonce(wallet, network, remotePendingNonce) // update local nonce to the latest
		// fmt.Printf("set local pending nonce to remote pending nonce: %d. RETURN\n", remotePendingNonce)
		return big.NewInt(int64(remotePendingNonce)), nil
	}
	// minedNonce < remotePendingNonce < localPendingNonce
	// in this case, local has more pending txs, this is the case when
	// the node doesn't have full pending txs as local, something is
	// wrong with the local txs.
	// TODO: give warnings and check pending txs, see if they are not found and update
	// local pending nonce respectively and retry not found txs, need to figure out
	// a mechanism to stop trying as well.
	// For now, we will just go ahead with localPendingNonce
	cm.setPendingNonce(wallet, network, localPendingNonce) // update local nonce to the latest
	// fmt.Printf("set local pending nonce to local pending nonce: %d. RETURN\n", localPendingNonce)
	return big.NewInt(int64(localPendingNonce)), nil
}

func (cm *ContextManager) getGasSettingInfo(network networks.Network) *GasInfo {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	return cm.gasSettings[network.GetChainID()]
}

func (cm *ContextManager) setGasInfo(network networks.Network, info *GasInfo) {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	cm.gasSettings[network.GetChainID()] = info
}

// implement a cache mechanism to be more efficient
func (cm *ContextManager) GasSetting(network networks.Network) (*GasInfo, error) {
	gasInfo := cm.getGasSettingInfo(network)
	if gasInfo == nil || time.Since(gasInfo.Timestamp) >= GAS_INFO_TTL {
		// gasInfo is not initiated or outdated
		reader := cm.Reader(network)
		gasPrice, gasTipCapGwei, err := reader.SuggestedGasSettings()
		if err != nil {
			return nil, fmt.Errorf("couldn't get gas settings in context manager: %w", err)
		}

		info := GasInfo{
			GasPrice:         gasPrice,
			BaseGasPrice:     nil,
			MaxPriorityPrice: gasTipCapGwei,
			FeePerGas:        gasPrice,
			Timestamp:        time.Now(),
		}
		cm.setGasInfo(network, &info)
		return &info, nil
	}
	return cm.getGasSettingInfo(network), nil
}

// BuildSendAllNativeTx builds a transaction to send all native tokens to the given address
// this function will use legacy transaction type to ensure there is not dusk left after the tx
// func (cm *ContextManager) buildSendAllNativeTx(
// 	from, to common.Address,
// 	nonce *big.Int,
// 	gasPrice float64,
// 	tipCapGwei float64,
// 	network networks.Network,
// ) (tx *types.Transaction, err error) {
// 	gasLimit := 21000
//
// 	if nonce == nil {
// 		nonce, err = cm.nonce(from, network)
// 		if err != nil {
// 			return nil, fmt.Errorf("couldn't get nonce of the wallet from any nodes: %w", err)
// 		}
// 	}
//
// 	if gasPrice == 0 {
// 		gasInfo, err := cm.GasSetting(network)
// 		if err != nil {
// 			return nil, fmt.Errorf("couldn't get gas price info from any nodes: %w", err)
// 		}
// 		gasPrice = gasInfo.GasPrice
// 	}
//
// 	balance, err := cm.Reader(network).GetBalance(from.Hex())
// 	if err != nil {
// 		return nil, fmt.Errorf("couldn't get balance of the wallet from any nodes: %w", err)
// 	}
//
// 	// amount to send = balance - gasLimit * gasPrice * 10^9
// 	amountToSend := big.NewInt(0).Sub(
// 		balance,
// 		big.NewInt(0).Mul(
// 			big.NewInt(int64(gasLimit)),
// 			jarviscommon.GweiToWei(gasPrice),
// 		),
// 	)
//
// 	amountToSend = big.NewInt(0).Sub(amountToSend, L2_GAS_OVERHEAD)
//
// 	if amountToSend.Cmp(big.NewInt(0)) <= 0 {
// 		return nil, fmt.Errorf("amount to send is less than the gas overhead")
// 	}
//
// 	return cm.BuildTx(
// 		types.LegacyTxType,
// 		from, to,
// 		nonce,
// 		amountToSend,
// 		uint64(gasLimit),
// 		gasPrice,
// 		0,
// 		nil,
// 		network,
// 	)
// }

func (cm *ContextManager) buildTx(
	txType uint8,
	from, to common.Address,
	nonce *big.Int,
	value *big.Int,
	gasLimit uint64,
	gasPrice float64,
	tipCapGwei float64,
	data []byte,
	network networks.Network,
) (tx *types.Transaction, err error) {
	if gasLimit == 0 {
		gasLimit, err = cm.Reader(network).EstimateExactGas(
			from.Hex(), to.Hex(),
			gasPrice,
			value,
			data,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"couldn't estimate gas. The tx is meant to revert or network error. Detail: %w",
				err,
			)
		}
	}

	if nonce == nil {
		nonce, err = cm.nonce(from, network)
		if err != nil {
			return nil, fmt.Errorf("couldn't get nonce of the wallet from any nodes: %w", err)
		}
	}

	if gasPrice == 0 {
		gasInfo, err := cm.GasSetting(network)
		if err != nil {
			return nil, fmt.Errorf("couldn't get gas price info from any nodes: %w", err)
		}
		gasPrice = gasInfo.GasPrice
		tipCapGwei = gasInfo.MaxPriorityPrice
	}

	return jarviscommon.BuildExactTx(
		txType,
		nonce.Uint64(),
		to.Hex(),
		value,
		gasLimit,
		gasPrice,
		tipCapGwei,
		data,
		network.GetChainID(),
	), nil
}

func (cm *ContextManager) signTx(
	wallet common.Address,
	tx *types.Transaction,
	network networks.Network,
) (signedAddr common.Address, signedTx *types.Transaction, err error) {
	acc := cm.Account(wallet)
	if acc == nil {
		acc, err = cm.UnlockAccount(wallet)
		if err != nil {
			return common.Address{}, nil, fmt.Errorf(
				"the wallet to sign txs is not registered in context manager",
			)
		}
	}
	return acc.SignTx(tx, big.NewInt(int64(network.GetChainID())))
}

func (cm *ContextManager) signTxAndBroadcast(
	wallet common.Address,
	tx *types.Transaction,
	network networks.Network,
) (signedTx *types.Transaction, successful bool, err BroadcastError) {
	signedAddr, tx, err := cm.signTx(wallet, tx, network)
	if err != nil {
		return tx, false, err
	}
	if signedAddr.Cmp(wallet) != 0 {
		return tx, false, fmt.Errorf(
			"signed from wrong address. You could use wrong hw or passphrase. Expected wallet: %s, signed wallet: %s",
			wallet.Hex(),
			signedAddr.Hex(),
		)
	}
	_, broadcasted, allErrors := cm.broadcastTx(tx)
	return tx, broadcasted, allErrors
}

func (cm *ContextManager) registerBroadcastedTx(tx *types.Transaction, network networks.Network) error {
	wallet, err := jarviscommon.GetSignerAddressFromTx(tx, big.NewInt(int64(network.GetChainID())))
	if err != nil {
		return fmt.Errorf("couldn't derive sender from the tx data in context manager: %s", err)
	}
	// update nonce
	cm.setPendingNonce(wallet, network, tx.Nonce())
	// update txs
	cm.setTx(wallet, network, tx)
	return nil
}

func (cm *ContextManager) broadcastTx(
	tx *types.Transaction,
) (hash string, broadcasted bool, err BroadcastError) {
	network, err := networks.GetNetworkByID(tx.ChainId().Uint64())
	// TODO: handle chainId 0 for old txs
	if err != nil {
		return "", false, BroadcastError(fmt.Errorf("tx is encoded with unsupported ChainID: %w", err))
	}
	hash, broadcasted, allErrors := cm.Broadcaster(network).BroadcastTx(tx)
	if broadcasted {
		cm.registerBroadcastedTx(tx, network)
	}
	return hash, broadcasted, NewBroadcastError(allErrors)
}

// MonitorTx non-blocking way to monitor the tx status, it returns a channel that will be closed when the tx monitoring is done
// the channel is supposed to receive the following values:
//  1. "mined" if the tx is mined
//  2. "slow" if the tx is too slow to be mined (so receiver might want to retry with higher gas price)
//  3. other strings if the tx failed and the reason is returned by the node or other debugging error message that the node can return
func (cm *ContextManager) MonitorTx(tx *types.Transaction, network networks.Network) <-chan string {
	txMonitor := cm.getTxMonitor(network)
	statusChan := make(chan string)
	monitorChan := txMonitor.MakeWaitChannel(tx.Hash().Hex())
	go func() {
		select {
		case status := <-monitorChan:
			if status.Status == "done" {
				statusChan <- "mined"
			} else if status.Status == "reverted" {
				// TODO: analyze to see what is the reason
				statusChan <- "reverted"
			} else if status.Status == "lost" {
				statusChan <- "lost"
			} else {
				// ignore other statuses
			}
		case <-time.After(10 * time.Second):
			statusChan <- "slow"
		}
		close(statusChan)
	}()
	return statusChan
}

func (cm *ContextManager) getTxStatuses(oldTxs map[string]*types.Transaction, network networks.Network) (statuses []jarviscommon.TxInfo, err error) {
	result := []jarviscommon.TxInfo{}

	for _, tx := range oldTxs {
		txInfo, _ := cm.Reader(network).TxInfoFromHash(tx.Hash().Hex())
		result = append(result, txInfo)
	}

	return result, nil
}

// EnsureTx ensures the tx is broadcasted and mined, it will retry until the tx is mined
func (cm *ContextManager) EnsureTx(
	txType uint8,
	from, to common.Address,
	value *big.Int,
	gasLimit uint64,
	gasPrice float64,
	tipCapGwei float64,
	data []byte,
	network networks.Network,
) (tx *types.Transaction, err error) {
	var oldTxs map[string]*types.Transaction = map[string]*types.Transaction{}
	var retryNonce *big.Int
	var retryGasPrice float64 = gasPrice
	var retryTipCap float64 = tipCapGwei

	// retry loop for at max 10 times
	for i := 0; i < 10; i++ {
		// always sleep for 5 seconds before retrying
		if i > 0 {
			time.Sleep(5 * time.Second)
		}

		tx, err = cm.buildTx(
			txType,        // tx type
			from,          // from address
			to,            // to address
			retryNonce,    // nonce (if nil means context manager will determine the nonce)
			value,         // amount
			gasLimit,      // gas limit
			retryGasPrice, // gas price
			retryTipCap,   // tip cap
			data,          // data
			network,       // network
		)

		if err != nil {
			return nil, fmt.Errorf("error building transaction: %s", err)
		}

		signexTx, successful, broadcastErr := cm.signTxAndBroadcast(from, tx, network)

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
			if broadcastErr == ErrInsufficientFund {
				// wait for 5 seconds and retry with the same nonce because the nonce is already acquired from
				// the context manager
				retryNonce = big.NewInt(int64(tx.Nonce()))
				continue
			}

			// 2. nonce is low
			if broadcastErr == ErrNonceIsLow {
				// in this case, we need to check if the last transaction is mined or it is lost
				statuses, err := cm.getTxStatuses(oldTxs, network)
				if err != nil {
					fmt.Printf("Error getting tx statuses in case where tx wasn't broadcasted because nonce is too low: %s. Ignore and continue the retry loop\n", err)
					// ignore the error and retry
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
					return signexTx, nil
				}

				// in this case, old txes weren't mined but the nonce is already used, it means
				// a different tx is with the same nonce was mined somewhere else
				// so we need to retry with a new nonce
				retryNonce = nil
				continue
			}

			// 3. gas limit is too low
			if broadcastErr == ErrGasLimitIsTooLow {
				// in this case, we just rely on the loop to hope it will finally have a better gas limit estimation
				// however, the same nonce must be used since it is acquired from the context manager already
				retryNonce = big.NewInt(int64(tx.Nonce()))
				continue
			}

			// 4. tx is known
			if broadcastErr == ErrTxIsKnown {
				// in this case, we need to speed up the tx by increasing the gas price and tip cap
				// however, it should be handled by the slow status gotten from the monitor tx below
				// so we just need to retry with the same nonce
				retryNonce = big.NewInt(int64(tx.Nonce()))
				continue
			}

			retryNonce = big.NewInt(int64(tx.Nonce()))
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
			return signexTx, nil
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
			retryGasPrice = jarviscommon.BigToFloat(tx.GasPrice(), 9) * 1.2
			retryTipCap = jarviscommon.BigToFloat(tx.GasTipCap(), 9) * 1.1
			retryNonce = big.NewInt(int64(tx.Nonce()))
			time.Sleep(5 * time.Second)
		}
	}

	return nil, fmt.Errorf("failed to ensure tx is mined after all retries")
}
