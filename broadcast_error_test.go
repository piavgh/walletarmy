package walletarmy

import (
	"errors"
	"testing"
)

func TestBroadcastError_Detection(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected BroadcastError
	}{
		{
			name:     "insufficient funds",
			err:      errors.New("insufficient funds for gas * price + value"),
			expected: ErrInsufficientFund,
		},
		{
			name:     "insufficient balance",
			err:      errors.New("account has insufficient balance"),
			expected: ErrInsufficientFund,
		},
		{
			name:     "not enough funds",
			err:      errors.New("not enough funds in account"),
			expected: ErrInsufficientFund,
		},
		{
			name:     "balance too low",
			err:      errors.New("balance too low to execute transaction"),
			expected: ErrInsufficientFund,
		},
		{
			name:     "nonce too low",
			err:      errors.New("nonce too low"),
			expected: ErrNonceIsLow,
		},
		{
			name:     "gas limit too low",
			err:      errors.New("gas limit too low"),
			expected: ErrGasLimitIsTooLow,
		},
		{
			name:     "already known",
			err:      errors.New("transaction already known"),
			expected: ErrTxIsKnown,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewBroadcastError(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBroadcastError_IsInsufficientFund(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"insufficient funds", errors.New("insufficient funds for gas * price + value"), true},
		{"insufficient balance", errors.New("account has insufficient balance"), true},
		{"not enough funds", errors.New("not enough funds in account"), true},
		{"balance too low", errors.New("balance too low to execute transaction"), true},
		{"other error", errors.New("some other error"), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil && tt.expected {
				t.Skip("nil error cannot match")
			}
			result := IsInsufficientFund(tt.err)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for error: %v", tt.expected, result, tt.err)
			}
		})
	}
}
