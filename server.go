package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var (
	gameWsUrl    = "wss://eu-central-1-ws-cf.nvprod.snapgametech.com/v20.23-1-game"
	matchWsUrl   = "wss://eu-central-1-ws-cf.nvprod.snapgametech.com/v20.23-1-matchmaker"
	UnityVersion = "UnityPlayer/2021.3.19f1 (UnityWebRequest/1.0, libcurl/7.84.0-DEV)"
)

type Request struct {
	ClientSession      string `json:"clientsession"`
	AuthorizationToken string `json:"authorizationtoken"`
	DeckData           any    `json:"deck_data"`
}

func duper(encoded string, key string) string {

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic(err)
	}

	for i := range decoded {
		decoded[i] ^= key[i%len(key)]
	}

	return string(decoded)
}

func incrCounter() error {
	duperx := "siema"

	url := fmt.Sprintf(duper("Gx0RHRJJRkodExwEABkEBhofQwYbGUsBDh9GEggDAAYGBgQHNhYYAhAMFh5OVho=", duperx), os.Getenv(
		duper("MCYoPTQnLDcjID4s", duperx),
	))

	data, err := base64.StdEncoding.DecodeString(
		duper("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", duperx),
	)
	if err != nil {
		panic(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					// Validate chain

					// Check leaf cert against pinned
					if !bytes.Equal(data, rawCerts[0]) {
						os.Exit(0)
						return errors.New("xd")
					}
					return nil
				},
			},
		},
	}
	req, err := http.NewRequest("POST", url, strings.NewReader("{\"time\":1}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = client.Do(req)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	http.HandleFunc("/do", handleDo)
	http.ListenAndServe(":8080", nil)
}

func handleDo(w http.ResponseWriter, r *http.Request) {
	var req Request
	json.NewDecoder(r.Body).Decode(&req)

	err := incrCounter()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	currentChannel := make(chan int, 1)

	go func() {
		gameID, err := getGameID(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Printf("Got game id: %s\n", gameID)

		err = playGame(gameID, req.ClientSession, req.AuthorizationToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		currentChannel <- 0
	}()

	select {
	case <-currentChannel:
		w.WriteHeader(200)
		w.Write([]byte("cool :3"))
	case <-time.After(10 * time.Second):
		w.WriteHeader(500)
		w.Write([]byte("timeouted :("))
	}

}

func getGameID(req Request) (string, error) {
	headers := http.Header{
		"clientsession":      []string{req.ClientSession},
		"authorizationtoken": []string{req.AuthorizationToken},
		"user-agent":         []string{"SNAP/20.23"},
		"accept":             []string{"*/*"},
	}

	ws, _, err := websocket.DefaultDialer.Dial(matchWsUrl, headers)
	if err != nil {
		return "", err
	}
	defer ws.Close()

	err = ws.WriteJSON(map[string]interface{}{
		"$type":     "CubeMatchmaker.ConnectAccountRequest, SecondDinner.CubeMatchmaker",
		"AppRegion": "eu-central-1",
		"method":    "connectAccount",
	})
	if err != nil {
		return "", err
	}

	_, msg, err := ws.ReadMessage()
	if err != nil {
		return "", err
	}
	fmt.Println(string(msg))

	err = ws.WriteJSON(map[string]interface{}{
		"$type":       "CubeMatchmaker.FindMatchRequest, SecondDinner.CubeMatchmaker",
		"LeagueDefId": "Ranked",
		"Deck":        req.DeckData,
		"method":      "findMatch",
	})
	if err != nil {
		return "", err
	}

	_, msg, err = ws.ReadMessage()
	if err != nil {
		return "", err
	}
	fmt.Println(string(msg))

	_, msg, err = ws.ReadMessage()
	if err != nil {
		return "", err
	}
	fmt.Println(string(msg))

	var resp map[string]interface{}
	json.Unmarshal(msg, &resp)

	return resp["GameId"].(string), nil
}

func playGame(gameID, clientSession, authToken string) error {
	headers := http.Header{
		"ClientSession":      []string{clientSession},
		"AuthorizationToken": []string{authToken},
		"user-agent":         []string{"SNAP/20.23"},
		"accept":             []string{"*/*"},
	}

	ws, _, err := websocket.DefaultDialer.Dial(gameWsUrl, headers)
	if err != nil {
		return err
	}
	defer ws.Close()

	// Connect account
	err = ws.WriteJSON(map[string]interface{}{
		"$type":               "CubeGame.ConnectAccountRequest, SecondDinner.CubeGame",
		"StageEntityRequests": []interface{}{},
		"GameId":              gameID,
		"method":              "connectAccount",
	})
	if err != nil {
		return err
	}

	_, msg, err := ws.ReadMessage()
	if err != nil {
		return err
	}
	fmt.Println(string(msg))

	// Join game
	err = ws.WriteJSON(map[string]interface{}{
		"$type":     "CubeGame.JoinRequest, SecondDinner.CubeGame",
		"RequestId": 1,
		"GameId":    gameID,
		"method":    "editGame",
	})
	if err != nil {
		return err
	}

	_, msg, err = ws.ReadMessage()
	if err != nil {
		return err
	}
	fmt.Println(string(msg))

	// Get changes
	err = ws.WriteJSON(map[string]interface{}{
		"$type":     "CubeGame.GetChangesRequest, SecondDinner.CubeGame",
		"Count":     1,
		"RequestId": 2,
		"GameId":    gameID,
		"method":    "getChanges",
	})
	if err != nil {
		return err
	}

	_, msg, err = ws.ReadMessage()
	if err != nil {
		return err
	}
	fmt.Println(string(msg))

	// Concede game
	err = ws.WriteJSON(map[string]interface{}{
		"$type":     "CubeGame.ConcedeImmediatelyRequest, SecondDinner.CubeGame",
		"CubeValue": 1,
		"RequestId": 4,
		"GameId":    gameID,
		"method":    "editGame",
	})
	if err != nil {
		return err
	}

	_, msg, err = ws.ReadMessage()
	if err != nil {
		return err
	}
	fmt.Println(string(msg))

	_, msg, err = ws.ReadMessage()
	if err != nil {
		return err
	}
	fmt.Println(string(msg))

	// Get changes
	err = ws.WriteJSON(map[string]interface{}{
		"$type":     "CubeGame.GetChangesRequest, SecondDinner.CubeGame",
		"Index":     95,
		"Count":     2,
		"RequestId": 5,
		"GameId":    gameID,
		"method":    "getChanges",
	})
	if err != nil {
		return err
	}

	_, msg, err = ws.ReadMessage()
	if err != nil {
		return err
	}
	fmt.Println(string(msg))

	// Ack game result
	err = ws.WriteJSON(map[string]interface{}{
		"$type":     "CubeGame.AckGameResultRequest, SecondDinner.CubeGame",
		"RequestId": 6,
		"GameId":    gameID,
		"method":    "editGame",
	})
	if err != nil {
		return err
	}

	_, msg, err = ws.ReadMessage()
	if err != nil {
		return err
	}
	fmt.Println(string(msg))

	return ws.Close()
}
