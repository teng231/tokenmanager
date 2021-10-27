package tokenmanager

import (
	"encoding/json"
	"log"
	"testing"
	"time"
)

type Claims struct {
	UserId int `json:"user_id"`
	RoleId int `json:"role_id"`
}

func TestGenRSAToken(t *testing.T) {
	mgr, err := CreateRSAToken("", "./test/jwtRS256.key")
	if err != nil {
		t.Fail()
	}
	tk, err := mgr.GenerateToken(Claims{UserId: 1}, 30*time.Minute)
	if err != nil {
		t.Fail()
	}
	log.Println(tk)
}

func TestParseRSAToken(t *testing.T) {
	tk := `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzIxMTEzOTYsImlhdCI6MTYzMjEwOTU5NiwicGF5bG9hZCI6eyJ1c2VyX2lkIjoxLCJyb2xlX2lkIjowfX0.Lumm89uR8X3NeKCJozzqdYf8WHJr1g-YjBFBA2_rxjRn5Uf0-nZGI0XisOOqcnXmIdMTrl1N3R4Ws7bsRrHwW_scQL3HRpK-_6fGOPzdv1IlN-JprWUeHvlbTqybPSyPwpkiEPi9n3vqSjeh-YOMw03F9xtXsI6Mpz5TVbjEEsRO06W5GZCx9FLxIckVodyawFdOnFsMYyFM44hIJMNex260VOQmPkBTUqunT966vYpQXOfkEcJaQQ4rfrarhhbbAEwXkpAIHksHOwKvsX3YtrYrT2QQY2Hhh7ZASaNWNs0KPQsVTrxR3mnz-tljz2LnXB_FGg8cdK3gfLzdHpYeK91C3WkTkhJNusNzgSlw2rtDFbNnaAgkskCjyi1BSKklI_UYWfu_U87OnGphuXwcuEOh_27827BhKfjDCC57EeKlgrqZPRCjExIHmMyw5YwMUM940cbkEJrzIA2qipfEFO-mfLgRrv2U7meuEo0MSlhjXfp9GQRQ1PMVnq36eU5boaAitGF6Gezw3vajsKi5_jcLlJyYLuFHSj79qv9iOG3yqbScB31tbDmmqP356Gj48kHMI_pkBESVAvqoIRceTch-CsTDh2VpwFiywIhKSxQ-50S5QoGRk0FN8LwUM0Xh737Dw95AlqV4JRXs_Y6PrCp-Jb-RbZ4ZVFsHTiqCqGI`
	mgr, err := CreateRSAToken("./test/jwtRS256.key.pub", "")
	if err != nil {
		t.Fail()
	}
	log.Print("xxxxxxxxxx", mgr)
	extractor, err := mgr.ParseToken(tk)
	if err != nil {
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
