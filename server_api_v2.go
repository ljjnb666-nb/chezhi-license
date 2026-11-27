package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"chezhi.local/licenseprototype/internal/license"
	"chezhi.local/licenseprototype/internal/proof"
)

const onlineCredentialTTL = 5 * time.Minute

func isV2Path(path string) bool {
	return path == "/api/v2" || strings.HasPrefix(path,"/api/v2/")
}

type proofRequest struct {
	Key string `json:"key"`
	PublicKey string `json:"public_key"`
	Operation string `json:"operation,omitempty"`
	Nonce string `json:"nonce,omitempty"`
	Signature string `json:"signature,omitempty"`
}

func decodeCanonicalHex(raw string,n int) ([]byte,bool) {
	if len(raw)!=2*n { return nil,false }
	b,err:=hex.DecodeString(raw)
	return b,err==nil && hex.EncodeToString(b)==raw
}

func proofOperation(raw string) (proof.Operation,bool) {
	switch raw {
	case "activate":return proof.Activate,true
	case "validate":return proof.Validate,true
	case "renew":return proof.Renew,true
	}
	return 0,false
}

func writeV2(w http.ResponseWriter,status int,id string,data any,code string) {
	w.Header().Set("Content-Type","application/json; charset=utf-8")
	w.Header().Set("Cache-Control","no-store")
	w.Header().Set("X-Request-ID",id)
	w.WriteHeader(status)
	result:=map[string]any{"version":"v2","request_id":id}
	if code!="" { result["error"]=apiError{Code:code} } else { result["data"]=data }
	_ = json.NewEncoder(w).Encode(result)
}

func (w Web) licenseV2(rw http.ResponseWriter,r *http.Request) {
	settings,shared:=r.Context().Value(serverRequestKey{}).(serverRequest)
	id:=settings.id
	if id=="" { id=randomToken()[:32] }
	fail:=func(status int,code string){writeV2(rw,status,id,nil,code)}
	if !shared || settings.config==nil || !settings.secure || settings.config.signer==nil || w.s.pg==nil {
		fail(404,"not_found");return
	}
	if len(r.Header.Values("Origin"))!=0 || r.Header.Get("Sec-Fetch-Site")!="" || r.Header.Get("Referer")!="" {
		fail(403,"browser_origin_forbidden");return
	}
	if r.Method!=http.MethodPost { rw.Header().Set("Allow","POST");fail(405,"method_not_allowed");return }
	media,_,err:=mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err!=nil || media!="application/json" { fail(415,"json_required");return }
	challenge:=r.URL.Path=="/api/v2/licenses/challenge"
	action:=strings.TrimPrefix(r.URL.Path,"/api/v2/licenses/")
	op,validOp:=proofOperation(action)
	if !challenge && (!validOp || r.URL.Path!="/api/v2/licenses/"+action) { fail(404,"not_found");return }
	if !w.consumeLicenseBudget(rw,r,fail) { return }
	r.Body=http.MaxBytesReader(rw,r.Body,4096)
	body,err:=io.ReadAll(r.Body)
	var large *http.MaxBytesError
	if errors.As(err,&large) { fail(413,"body_too_large");return }
	var request proofRequest
	if err!=nil || !utf8.Valid(body) || uniqueJSON(body)!=nil { fail(400,"invalid_json");return }
	dec:=json.NewDecoder(bytes.NewReader(body));dec.DisallowUnknownFields()
	if dec.Decode(&request)!=nil { fail(400,"invalid_json");return }
	// Exact field sets; reject aliases, null fields and case-insensitive
	// struct decoder aliases, rather than interpreting ambiguous requests.
	var fields map[string]json.RawMessage
	if json.Unmarshal(body,&fields)!=nil { fail(400,"invalid_json");return }
	expected:=[]string{"key","public_key","nonce","signature"}
	if challenge { expected=[]string{"key","public_key","operation"} }
	if len(fields)!=len(expected) { fail(400,"invalid_input");return }
	for _,name:=range expected {
		value,ok:=fields[name]
		if !ok || len(value)==0 || value[0]!='"' { fail(400,"invalid_input");return }
	}
	if len(request.Key)==0 || len(request.Key)>100 { fail(400,"invalid_input");return }
	public,ok:=decodeCanonicalHex(request.PublicKey,65)
	if !ok { fail(400,"invalid_input");return }
	if _,_,err:=proof.DevicePublicKey(public);err!=nil { fail(400,"invalid_input");return }
	var hash proof.Digest
	b,err:=hex.DecodeString(license.HashKey(request.Key))
	if err!=nil || len(b)!=32 { fail(400,"invalid_input");return }
	copy(hash[:],b)
	signer:=settings.config.signer
	if challenge {
		op,validOp=proofOperation(request.Operation)
		if !validOp { fail(400,"invalid_input");return }
		c,err:=w.s.pg.issueProofChallenge(r.Context(),signer.policy.scope,op,hash,public)
		if err!=nil { writeProofFailure(fail,err);return }
		transcript,err:=c.Transcript()
		if err!=nil { fail(503,"unavailable");return }
		writeV2(rw,200,id,map[string]any{
			"nonce":hex.EncodeToString(c.Nonce[:]),"epoch":c.Epoch,
			"issued_at":c.IssuedAt,"expires_at":c.ExpiresAt,
			"deployment":hex.EncodeToString(c.Scope.Deployment[:]),"product":c.Scope.Product,
			"transcript":hex.EncodeToString(transcript),
		},"")
		return
	}
	nonceBytes,ok:=decodeCanonicalHex(request.Nonce,32)
	signature,ok2:=decodeCanonicalHex(request.Signature,64)
	if !ok || !ok2 { fail(400,"invalid_input");return }
	var nonce proof.Digest
	copy(nonce[:],nonceBytes)
	result,err:=w.s.pg.authorizeProof(r.Context(),nonce,signer.policy.scope,op,hash,public,signature,signer.private,onlineCredentialTTL)
	if err!=nil { writeProofFailure(fail,err);return }
	c:=result.Claims
	transcript,err:=c.Transcript()
	if err!=nil { fail(503,"unavailable");return }
	writeV2(rw,200,id,map[string]any{
		"valid":true,"license_id":hex.EncodeToString(c.License[:]),
		"device":hex.EncodeToString(c.Device[:]),"key_id":hex.EncodeToString(c.KeyID[:]),
		"nonce":hex.EncodeToString(c.Nonce[:]),
		"deployment":hex.EncodeToString(c.Scope.Deployment[:]),"product":c.Scope.Product,
		"revision":c.Revision,"issued_at":c.IssuedAt,"expires_at":c.ExpiresAt,
		"license_expires_at":c.LicenseExpiresAt,"transcript":hex.EncodeToString(transcript),
		"signature":hex.EncodeToString(result.Signature),
	},"")
}

func writeProofFailure(fail func(int,string),err error) {
	switch {
	case errors.Is(err,errChallengeInvalid),errors.Is(err,errLegacyBinding),errors.Is(err,errSecureBinding):
		fail(403,"authorization_denied")
	case errors.Is(err,errChallengeCapacity):
		fail(503,"busy")
	default:
		fail(503,"unavailable")
	}
}
