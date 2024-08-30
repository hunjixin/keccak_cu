module github/hunjixin/keccak_cu

go 1.22.3

require (
	github.com/ALTree/bigfloat v0.2.0
	github.com/ethereum/go-ethereum v1.14.5
	github.com/holiman/uint256 v1.2.4
	github.com/pkg/errors v0.9.1
	gorgonia.org/cu v0.9.5
)

replace gorgonia.org/cu => github.com/hunjixin/cu v0.0.0-20240618140529-d11ba74b75b6

require (
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/google/uuid v1.3.0 // indirect
	golang.org/x/crypto v0.22.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
)
