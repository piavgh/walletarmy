package walletarmy

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/tranvictor/jarvis/networks"
)

// MockHook for testing hooks
func mockHook(tx *types.Transaction, err error) error {
	return nil
}

func TestWalletManager_R(t *testing.T) {
	wm := &WalletManager{}

	req := wm.R()

	assert.NotNil(t, req)
	assert.Equal(t, wm, req.wm)
	assert.Equal(t, big.NewInt(0), req.value)
	assert.Equal(t, 0, req.numRetries)
	assert.Equal(t, time.Duration(0), req.sleepDuration)
	assert.Equal(t, uint8(0), req.txType)
	assert.Equal(t, common.Address{}, req.from)
	assert.Equal(t, common.Address{}, req.to)
	assert.Equal(t, uint64(0), req.gasLimit)
	assert.Equal(t, uint64(0), req.extraGasLimit)
	assert.Equal(t, float64(0), req.gasPrice)
	assert.Equal(t, float64(0), req.extraGasPrice)
	assert.Equal(t, float64(0), req.tipCapGwei)
	assert.Equal(t, float64(0), req.extraTipCapGwei)
	assert.Nil(t, req.data)
	assert.Equal(t, networks.EthereumMainnet, req.network)
	assert.Nil(t, req.beforeSignAndBroadcastHook)
	assert.Nil(t, req.afterSignAndBroadcastHook)
}

func TestTxRequest_SetNumRetries(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetNumRetries(5)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, 5, req.numRetries)
}

func TestTxRequest_SetSleepDuration(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()
	duration := 2 * time.Second

	result := req.SetSleepDuration(duration)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, duration, req.sleepDuration)
}

func TestTxRequest_SetTxType(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetTxType(2)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, uint8(2), req.txType)
}

func TestTxRequest_SetFrom(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()
	fromAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")

	result := req.SetFrom(fromAddr)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, fromAddr, req.from)
}

func TestTxRequest_SetTo(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()
	toAddr := common.HexToAddress("0x0987654321098765432109876543210987654321")

	result := req.SetTo(toAddr)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, toAddr, req.to)
}

func TestTxRequest_SetValue(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	t.Run("with valid value", func(t *testing.T) {
		value := big.NewInt(1000000000000000000) // 1 ETH in wei
		result := req.SetValue(value)

		assert.Equal(t, req, result) // Should return self for chaining
		assert.Equal(t, value, req.value)
	})

	t.Run("with nil value", func(t *testing.T) {
		originalValue := req.value
		result := req.SetValue(nil)

		assert.Equal(t, req, result)              // Should return self for chaining
		assert.Equal(t, originalValue, req.value) // Should not change when nil
	})
}

func TestTxRequest_SetGasLimit(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetGasLimit(21000)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, uint64(21000), req.gasLimit)
}

func TestTxRequest_SetExtraGasLimit(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetExtraGasLimit(5000)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, uint64(5000), req.extraGasLimit)
}

func TestTxRequest_SetGasPrice(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetGasPrice(20.5)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, 20.5, req.gasPrice)
}

func TestTxRequest_SetExtraGasPrice(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetExtraGasPrice(5.5)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, 5.5, req.extraGasPrice)
}

func TestTxRequest_SetTipCapGwei(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetTipCapGwei(2.0)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, 2.0, req.tipCapGwei)
}

func TestTxRequest_SetExtraTipCapGwei(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetExtraTipCapGwei(1.5)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, 1.5, req.extraTipCapGwei)
}

func TestTxRequest_SetData(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()
	data := []byte{0x01, 0x02, 0x03, 0x04}

	result := req.SetData(data)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, data, req.data)
}

func TestTxRequest_SetNetwork(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()
	network := networks.EthereumMainnet

	result := req.SetNetwork(network)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.Equal(t, network, req.network)
}

func TestTxRequest_SetBeforeSignAndBroadcastHook(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetBeforeSignAndBroadcastHook(mockHook)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.NotNil(t, req.beforeSignAndBroadcastHook)
}

func TestTxRequest_SetAfterSignAndBroadcastHook(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	result := req.SetAfterSignAndBroadcastHook(mockHook)

	assert.Equal(t, req, result) // Should return self for chaining
	assert.NotNil(t, req.afterSignAndBroadcastHook)
}

func TestTxRequest_BuilderPatternChaining(t *testing.T) {
	wm := &WalletManager{}
	fromAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	toAddr := common.HexToAddress("0x0987654321098765432109876543210987654321")
	value := big.NewInt(1000000000000000000) // 1 ETH in wei
	data := []byte{0x01, 0x02, 0x03, 0x04}
	network := networks.EthereumMainnet
	duration := 2 * time.Second

	// Test chaining multiple methods together
	req := wm.R().
		SetNumRetries(3).
		SetSleepDuration(duration).
		SetTxType(2).
		SetFrom(fromAddr).
		SetTo(toAddr).
		SetValue(value).
		SetGasLimit(21000).
		SetExtraGasLimit(1000).
		SetGasPrice(20.5).
		SetExtraGasPrice(5.0).
		SetTipCapGwei(2.0).
		SetExtraTipCapGwei(1.0).
		SetData(data).
		SetNetwork(network).
		SetBeforeSignAndBroadcastHook(mockHook).
		SetAfterSignAndBroadcastHook(mockHook)

	// Verify all values were set correctly
	assert.Equal(t, 3, req.numRetries)
	assert.Equal(t, duration, req.sleepDuration)
	assert.Equal(t, uint8(2), req.txType)
	assert.Equal(t, fromAddr, req.from)
	assert.Equal(t, toAddr, req.to)
	assert.Equal(t, value, req.value)
	assert.Equal(t, uint64(21000), req.gasLimit)
	assert.Equal(t, uint64(1000), req.extraGasLimit)
	assert.Equal(t, 20.5, req.gasPrice)
	assert.Equal(t, 5.0, req.extraGasPrice)
	assert.Equal(t, 2.0, req.tipCapGwei)
	assert.Equal(t, 1.0, req.extraTipCapGwei)
	assert.Equal(t, data, req.data)
	assert.Equal(t, network, req.network)
	assert.NotNil(t, req.beforeSignAndBroadcastHook)
	assert.NotNil(t, req.afterSignAndBroadcastHook)
}

func TestTxRequest_MultipleSettersOfSameType(t *testing.T) {
	wm := &WalletManager{}
	req := wm.R()

	// Test that calling the same setter multiple times overwrites the previous value
	req.SetNumRetries(5).SetNumRetries(10).SetNumRetries(15)
	assert.Equal(t, 15, req.numRetries)

	req.SetGasPrice(10.0).SetGasPrice(20.0).SetGasPrice(30.0)
	assert.Equal(t, 30.0, req.gasPrice)

	value1 := big.NewInt(100)
	value2 := big.NewInt(200)
	value3 := big.NewInt(300)
	req.SetValue(value1).SetValue(value2).SetValue(value3)
	assert.Equal(t, value3, req.value)
}
