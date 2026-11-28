package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminAdmissionIsolation(t *testing.T) {
	h:=&serverRouter{
		config:&serverConfig{host:"127.0.0.1:18443"},
		admin:make(chan struct{},8),
		adminIssue:make(chan struct{},1),
		public:make(chan struct{},3),
	}
	read,ri:=h.adminQueue(httptest.NewRequest(http.MethodGet,"http://127.0.0.1:18443/?view=overview",nil))
	write,wi:=h.adminQueue(httptest.NewRequest(http.MethodPost,"http://127.0.0.1:18443/?view=issue",nil))
	if ri!=0 || wi!=1 || read==write || cap(read)!=8 || cap(write)!=1 {
		t.Fatal("unexpected admission layout")
	}
	for _,target:=range []string{"/account/password","/login","/?view=cards","/?view=issue&extra=1","/?view=issue&view=issue"} {
		queue,index:=h.adminQueue(httptest.NewRequest(http.MethodPost,"http://127.0.0.1:18443"+target,nil))
		if queue!=read || index!=0 {t.Fatalf("unexpected reserved lane for %s",target)}
	}
	for i:=0;i<cap(read);i++ {read<-struct{}{}}
	select {
	case write<-struct{}{}:
	default:t.Fatal("read saturation starved writer")
	}
	reject:=func(method,path string) {
		t.Helper()
		r:=httptest.NewRequest(method,"http://127.0.0.1:18443"+path,nil)
		w:=httptest.NewRecorder()
		h.ServeHTTP(w,r)
		if w.Code!=503 || w.Header().Get("Retry-After")!="1" {
			t.Fatalf("%s %s: status=%d",method,path,w.Code)
		}
	}
	reject(http.MethodGet,"/?view=overview")
	reject(http.MethodPost,"/?view=issue")
	for i:=0;i<cap(h.public);i++ {h.public<-struct{}{}}
	reject(http.MethodPost,"/api/v2/licenses/renew")
	if h.admissionRejected[0].Load()!=1 || h.admissionRejected[1].Load()!=1 ||
		h.admissionRejected[2].Load()!=1 || h.admissionRejected[3].Load()!=0 {
		t.Fatal("incorrect fixed-category admission counters")
	}
	<-write
	select {
	case write<-struct{}{}:
	default:t.Fatal("writer could not recover while readers remain saturated")
	}
	<-write
	for i:=0;i<cap(read);i++ {<-read}
	for i:=0;i<cap(h.public);i++ {<-h.public}
}
