package tokenmanager

import (
	"encoding/json"
	"log"
	"testing"
	"time"
)

func TestGenHmacToken(t *testing.T) {
	mgr, err := CreateHMACToken("./test/secret")
	if err != nil {
		t.Fail()
	}
	_tk, err := mgr.GenerateHmacToken(Claims{UserId: 1}, 30*time.Second)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	log.Println(_tk)
}

func TestParseHmacToken(t *testing.T) {
	mgr, err := CreateHMACToken("1234@sdfdfda}")
	if err != nil {
		log.Print(1, err)
		t.Fail()
	}
	_tk, err := mgr.GenerateHmacToken(Claims{UserId: 1}, 30*time.Second)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	extractor, err := mgr.ParseHmacToken(_tk)
	if err != nil {
		log.Print(2, err)
		t.Fail()
	}
	bin, err := json.Marshal(extractor)
	if err != nil {
		log.Print(3, err)
		t.Fail()
	}
	claim := &Claims{}
	json.Unmarshal(bin, claim)
	log.Println(claim)
	if claim.UserId != 1 {
		t.Fail()
	}

	// -- with token expired
	expiredTk := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzIxMDg3MTcsImlhdCI6MTYzMjEwODY4NywicGF5bG9hZCI6eyJ1c2VyX2lkIjoxLCJyb2xlX2lkIjowfX0.R2mcIpb03PuGSTXLtWLEgDdzuJvBkE-F7ukfALlUtKk`
	extractor, err = mgr.ParseHmacToken(expiredTk)
	if err == nil {
		log.Print(extractor)
		t.Fail()
	}
}
