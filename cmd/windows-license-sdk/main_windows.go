//go:build windows && amd64 && cgo

// This development DLL is intentionally stateless and has no offline grant.
package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef int32_t (*chezhi_sign_fn)(void *ctx, const uint8_t *digest32, uint8_t *signature64);
static inline int32_t call_sign(chezhi_sign_fn fn, void *ctx, uint8_t *buf) {
    return fn(ctx, buf, buf + 32);
}
*/
import "C"

import (
	"context"
	"crypto/ed25519"
	"errors"
	"unsafe"

	"chezhi.local/licenseprototype/internal/proof"
	"chezhi.local/licenseprototype/internal/sdk"
)

//export ChezhiLicenseABIVersion
func ChezhiLicenseABIVersion() C.uint32_t { return 1 }

//export ChezhiLicenseAuthorize
func ChezhiLicenseAuthorize(origin *C.uint8_t, originLen C.uint32_t,
	deployment *C.uint8_t, trusted *C.uint8_t, card *C.uint8_t, cardLen C.uint32_t,
	device *C.uint8_t, signer C.chezhi_sign_fn, userContext unsafe.Pointer,
	operation C.uint32_t, output *C.uint8_t, outputLen C.uint32_t) (status C.int32_t) {
	// Buffers are owned by the caller. Fixed-length pointers must be valid;
	// pointers and output must not overlap. ABI cannot validate arbitrary
	// foreign address ranges. Nothing is retained after return.
	if output==nil || outputLen!=sdk.ResultSize { return C.int32_t(sdk.InvalidInput) }
	out:=unsafe.Slice((*byte)(unsafe.Pointer(output)),sdk.ResultSize)
	clear(out)
	defer func(){
		if recover()!=nil { clear(out);status=C.int32_t(sdk.InternalFailure) }
	}()
	if origin==nil || originLen==0 || originLen>2048 || deployment==nil || trusted==nil ||
		card==nil || cardLen==0 || cardLen>100 || device==nil || signer==nil ||
		operation<1 || operation>3 { return C.int32_t(sdk.InvalidInput) }
	var scope proof.Digest
	copy(scope[:],C.GoBytes(unsafe.Pointer(deployment),32))
	pub:=ed25519.PublicKey(C.GoBytes(unsafe.Pointer(trusted),32))
	point:=C.GoBytes(unsafe.Pointer(device),65)
	provider,err:=sdk.NewDeviceSigner(point,func(d [32]byte)(out [64]byte,err error){
		// Foreign callback receives only C-owned temporary memory, not a Go
		// pointer. It must be synchronous and must not retain either pointer.
		buf:=C.calloc(1,96)
		if buf==nil {return out,errors.New("callback buffer allocation failed")}
		defer C.free(buf)
		defer C.memset(buf,0,96)
		copy(unsafe.Slice((*byte)(buf),32),d[:])
		if C.call_sign(signer,userContext,(*C.uint8_t)(buf))!=0 { return out,errors.New("device provider failed") }
		copy(out[:],unsafe.Slice((*byte)(buf),96)[32:])
		return
	})
	if err!=nil {return C.int32_t(sdk.InvalidInput)}
	r,s:=sdk.Authorize(context.Background(),sdk.Config{
		Origin:string(C.GoBytes(unsafe.Pointer(origin),C.int(originLen))),Deployment:scope,TrustedKey:pub,
	},proof.Operation(operation),string(C.GoBytes(unsafe.Pointer(card),C.int(cardLen))),provider)
	if s==sdk.OK {r.Encode(out)}
	return C.int32_t(s)
}

func main() {}
