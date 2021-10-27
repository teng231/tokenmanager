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
	tk, err := mgr.GenerateHmacToken(Claims{UserId: 1}, 30*time.Second)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	log.Println(tk)
}

func TestParseHmacToken(t *testing.T) {
	tk := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzIxMDg3MTcsImlhdCI6MTYzMjEwODY4NywicGF5bG9hZCI6eyJ1c2VyX2lkIjoxLCJyb2xlX2lkIjowfX0.R2mcIpb03PuGSTXLtWLEgDdzuJvBkE-F7ukfALlUtKk`
	mgr, err := CreateHMACToken("./test/secret")
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	extractor, err := mgr.ParseHmacToken(tk)
	if err != nil {
		log.Print(err)
		t.Fail()
	}
	bin, err := json.Marshal(extractor)
	if err != nil {
		t.Fail()
	}
	claim := &Claims{}
	json.Unmarshal(bin, claim)
	log.Println(claim)
	if claim.UserId != 1 {
		t.Fail()
	}
}
