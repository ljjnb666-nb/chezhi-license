package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"chezhi.local/licenseprototype/internal/license"
	"chezhi.local/licenseprototype/internal/proof"
)

// Construct a historical fixture using only the original schema's SQL,
// rather than calling a modern runtime against an unsupported old schema.
func seedHistoricalCards(t *testing.T,s *Store,days,n,cents int,channel,ref string) {
	t.Helper()
	err:=s.pg.transaction(context.Background(),nil,func(ctx context.Context,tx *sql.Tx)error{
		now:=time.Now().UTC()
		for i:=0;i<n;i++{
			_,hash,prefix,err:=license.GenerateKey()
			if err!=nil{return err}
			c:=Card{ID:hash[:24],Hash:hash,Prefix:prefix,Days:days,SaleRef:ref,Channel:channel,AmountCents:cents,Created:now}
			if i==0 { if err:=insertOrder(ctx,tx,c);err!=nil{return err} }
			if err:=insertCard(ctx,tx,c);err!=nil{return err}
			if err:=appendAudit(ctx,tx,Audit{At:now,Action:"issue",CardID:c.ID,Actor:"admin"});err!=nil{return err}
		}
		return nil
	})
	if err!=nil{t.Fatal(err)}
}

func TestPostgresSigningPolicyV2(t *testing.T) {
	s,dsn:=postgresFixture(t)
	pgInitialize(t,s)
	ctx:=context.Background()
	var name string
	if err:=s.pg.db.QueryRow("SELECT current_database()").Scan(&name);err!=nil{t.Fatal(err)}
	pub,private,err:=ed25519.GenerateKey(rand.Reader)
	if err!=nil{t.Fatal(err)}
	publicHex:=hex.EncodeToString(pub)
	if err:=s.pg.setSigningPolicy(ctx,name,"none",publicHex);err!=nil{t.Fatal(err)}
	if err:=s.pg.setSigningPolicy(ctx,name,"none",publicHex);err==nil{t.Fatal("policy reinitialized")}
	if err:=s.pg.verifyDatabase(ctx,"--migrator");err!=nil{t.Fatal(err)}
	t.Setenv("CHEZHI_SIGNING_KEY_FILE","")
	if _,err:=s.pg.configureSigner(ctx);err==nil{t.Fatal("missing signer accepted")}
	file:=filepath.Join(t.TempDir(),"signing-seed")
	if err:=os.WriteFile(file,[]byte(hex.EncodeToString(private.Seed())+"\n"),0600);err!=nil{t.Fatal(err)}
	t.Setenv("CHEZHI_SIGNING_KEY_FILE",file)
	signer,err:=s.pg.configureSigner(ctx)
	if err!=nil || signer==nil{t.Fatal("configure signer",err)}
	peer,err:=openPostgres(ctx,dsn)
	if err!=nil{t.Fatal(err)}
	defer peer.db.Close()
	if _,err:=peer.configureSigner(ctx);err!=nil{t.Fatal("peer signer",err)}
	keys,err:=s.issue(30,1,100,"test","secure-only-fixture")
	if err!=nil{t.Fatal(err)}
	legacy,err:=s.validate(keys[0],"legacy")
	if err!=nil || legacy.Valid || legacy.Reason!="secure_protocol_required"{t.Fatal("new card permits legacy activation",legacy,err)}

	dev,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil{t.Fatal(err)}
	device:=elliptic.Marshal(dev.Curve,dev.X,dev.Y)
	hashText:=license.HashKey(keys[0])
	hashBytes,_:=hex.DecodeString(hashText)
	var hash proof.Digest
	copy(hash[:],hashBytes)
	config:=&serverConfig{secure:true,signer:signer,licenseRate:60,publicRate:240}
	// Real PostgreSQL, real TLS HTTP transport, explicit request context.
	// Full server process and proxy integration are a separate acceptance gate.
	handler:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		settings:=serverRequest{config:config,source:digestSecret("v2-fixture"),id:"fixture",secure:r.TLS!=nil}
		Web{s:s}.licenseV2(w,r.WithContext(context.WithValue(r.Context(),serverRequestKey{},settings)))
	})
	server:=httptest.NewTLSServer(handler)
	defer server.Close()
	post:=func(path string,body map[string]string,want int)map[string]json.RawMessage{
		t.Helper()
		b,err:=json.Marshal(body)
		if err!=nil{t.Fatal(err)}
		resp,err:=server.Client().Post(server.URL+"/api/v2/licenses/"+path,"application/json",bytes.NewReader(b))
		if err!=nil{t.Fatal(err)}
		defer resp.Body.Close()
		if resp.StatusCode!=want{t.Fatalf("%s: status=%d want=%d",path,resp.StatusCode,want)}
		var reply struct{Version string `json:"version"`;Data map[string]json.RawMessage `json:"data"`}
		if err:=json.NewDecoder(resp.Body).Decode(&reply);err!=nil || reply.Version!="v2"{t.Fatal("bad envelope",err)}
		return reply.Data
	}
	get:=func(data map[string]json.RawMessage,name string,out any){
		t.Helper()
		if err:=json.Unmarshal(data[name],out);err!=nil{t.Fatal(name,err)}
	}
	challengeBody:=map[string]string{"key":keys[0],"public_key":hex.EncodeToString(device),"operation":"activate"}
	ch:=post("challenge",challengeBody,200)
	var nonceHex string
	var issued,expires int64
	var epoch uint64
	get(ch,"nonce",&nonceHex);get(ch,"issued_at",&issued);get(ch,"expires_at",&expires);get(ch,"epoch",&epoch)
	nonceBytes,_:=hex.DecodeString(nonceHex)
	var nonce proof.Digest
	copy(nonce[:],nonceBytes)
	_,fp,err:=proof.DevicePublicKey(device)
	if err!=nil{t.Fatal(err)}
	challenge:=proof.Challenge{Scope:signer.policy.scope,Operation:proof.Activate,Nonce:nonce,CardHash:hash,Device:fp,Epoch:epoch,IssuedAt:issued,ExpiresAt:expires}
	sig:=signTestChallenge(t,challenge,dev)
	body:=map[string]string{"key":keys[0],"public_key":hex.EncodeToString(device),"nonce":nonceHex,"signature":hex.EncodeToString(sig)}
	post("validate",body,403)
	credential:=post("activate",body,200)
	var signatureHex,transcriptHex string
	get(credential,"signature",&signatureHex);get(credential,"transcript",&transcriptHex)
	signed,_:=hex.DecodeString(signatureHex)
	transcript,_:=hex.DecodeString(transcriptHex)
	if !ed25519.Verify(pub,transcript,signed){t.Fatal("invalid credential signature")}
	post("activate",body,403)
	lease,err:=s.pg.attachDeployment(ctx,"local")
	if err!=nil{t.Fatal(err)}
	newPub,_,err:=ed25519.GenerateKey(rand.Reader)
	if err!=nil{lease();t.Fatal(err)}
	currentID:=sha256.Sum256(pub)
	newHex:=hex.EncodeToString(newPub)
	if err:=peer.setSigningPolicy(ctx,name,fmt.Sprintf("%x",currentID),newHex);err==nil{lease();t.Fatal("online rotation accepted")}
	lease()
	if err:=peer.setSigningPolicy(ctx,name,fmt.Sprintf("%x",currentID),newHex);err!=nil{t.Fatal(err)}
	if _,err:=peer.configureSigner(ctx);err==nil{t.Fatal("old private key accepted after rotation")}
	rotated,err:=readSigningPolicy(ctx,peer.db)
	if err!=nil || rotated.scope==signer.policy.scope{t.Fatal("rotation scope not replaced",err)}
}
