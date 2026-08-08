package compiler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/aurora-capcompute/capcompute"
	extism "github.com/extism/go-sdk"
)

type Compiler interface {
	Compile(ctx context.Context, id string, wasm []byte) (*capcompute.Program, error)
}

func New(memoryPages uint32) Compiler {
	return &impl{memoryPages}
}

type impl struct {
	memoryPages uint32
}

func (compiler *impl) Compile(ctx context.Context, id string, wasm []byte) (*capcompute.Program, error) {
	sum := sha256.Sum256(wasm)
	digest := hex.EncodeToString(sum[:])
	image, err := capcompute.NewProgram(ctx, capcompute.Config{
		Image: extism.Manifest{
			Wasm: []extism.Wasm{extism.WasmData{Data: wasm, Hash: digest, Name: id}},
		},
		PluginConfig:   extism.PluginConfig{EnableWasi: true},
		MaxMemoryPages: compiler.memoryPages,
	})
	if err != nil {
		return nil, fmt.Errorf("compile program %q: %w", id, err)
	}
	return image, nil
}
