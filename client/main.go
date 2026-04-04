// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	url1 "net/url"
	"os"

	"os/signal"
	"regexp"

	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bschaatsbergen/dnsdialer"
	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

type getCredsFunc func(string) (string, string, string, error)

const GlobalUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

func performPoW(input string, difficulty int) string {
	prefix := strings.Repeat("0", difficulty)
	var nonce int64 = 0
	for {
		data := fmt.Sprintf("%s%d", input, nonce)
		hash := sha256.Sum256([]byte(data))
		hashHex := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hashHex, prefix) {
			return hashHex
		}
		nonce++
		if nonce > 10000000 {
			return ""
		}
	}
}

func solveSmartCaptcha(httpClient *http.Client, redirectUri string) (string, error) {
	u, err := url1.Parse(redirectUri)
	if err != nil {
		return "", err
	}
	sessionToken := u.Query().Get("session_token")

	// Имитируем небольшую задержку перед загрузкой (человеческий фактор)
	time.Sleep(1 * time.Second)

	respPage, err := httpClient.Get(redirectUri)
	if err != nil {
		return "", err
	}
	defer respPage.Body.Close()
	html, _ := io.ReadAll(respPage.Body)
	htmlStr := string(html)

	reInput := regexp.MustCompile(`const powInput = "([^"]+)"`)
	reDiff := regexp.MustCompile(`const difficulty = (\d+)`)
	powInput := sessionToken
	if m := reInput.FindStringSubmatch(htmlStr); len(m) > 1 {
		powInput = m[1]
	}
	difficulty := 2
	if m := reDiff.FindStringSubmatch(htmlStr); len(m) > 1 {
		difficulty, _ = strconv.Atoi(m[1])
	}

	commonHeaders := func(req *http.Request) {
		req.Header.Set("User-Agent", GlobalUA)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", redirectUri)
	}

	params := url1.Values{}
	params.Set("session_token", sessionToken)
	params.Set("domain", "vk.com")

	reqS, _ := http.NewRequest("POST", "https://api.vk.ru/method/captchaNotRobot.settings?v=5.131", strings.NewReader(params.Encode()))
	commonHeaders(reqS)
	httpClient.Do(reqS)

	params.Set("browser_fp", "539e030fbe394e70ac36a05d791eb7da")
	deviceInfo := `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1872,"innerHeight":904,"devicePixelRatio":1,"language":"ru","languages":["ru","en"],"webdriver":false,"hardwareConcurrency":12,"deviceMemory":8,"colorDepth":24,"touchSupport":false}`
	params.Set("device", deviceInfo)
	reqD, _ := http.NewRequest("POST", "https://api.vk.ru/method/captchaNotRobot.componentDone?v=5.131", strings.NewReader(params.Encode()))
	commonHeaders(reqD)
	httpClient.Do(reqD)

	powHash := performPoW(powInput, difficulty)

	// Пауза перед финальным чеком (как будто кликнули)
	time.Sleep(500 * time.Millisecond)

	params.Del("device")
	params.Set("hash", powHash)
	params.Set("accelerometer", "[]")
	params.Set("gyroscope", "[]")
	params.Set("motion", "[]")
	params.Set("cursor", "[]")
	params.Set("taps", "[]")

	reqC, _ := http.NewRequest("POST", "https://api.vk.ru/method/captchaNotRobot.check?v=5.131", strings.NewReader(params.Encode()))
	commonHeaders(reqC)
	respC, err := httpClient.Do(reqC)
	if err != nil {
		return "", err
	}
	defer respC.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(respC.Body).Decode(&result)

	if res, ok := result["response"].(map[string]interface{}); ok {
		if token, ok := res["success_token"].(string); ok && token != "" {
			return token, nil
		}
	}
	return "", fmt.Errorf("solve status fail: %v", result)
}

func getVkCreds(link string, dialer *dnsdialer.Dialer) (string, string, string, error) {
	name := generateName()
	uagent := getRandomProfile()
	escapedName := url1.QueryEscape(name)

	var currentCaptchaToken string
	var currentCaptchaSid string

	var doRequest func(string, string) (map[string]interface{}, error)
	doRequest = func(data string, url string) (resp map[string]interface{}, err error) {
		jar, _ := cookiejar.New(nil)
		client := &http.Client{
			Jar:     jar,
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DialContext:         dialer.DialContext,
			},
		}

		finalData := data
		if currentCaptchaToken != "" && currentCaptchaSid != "" {
			// Передаем токен во всех возможных полях для надежности
			finalData = fmt.Sprintf("%s&captcha_sid=%s&captcha_key=%s&captcha_token=%s&success_token=%s",
				data, currentCaptchaSid, currentCaptchaToken, currentCaptchaToken, currentCaptchaToken)
		}

		defer client.CloseIdleConnections()
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(finalData)))
		if err != nil {
			return nil, err
		}

		req.Header.Add("User-Agent", uagent.UserAgent)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		// captcha req
		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}

		if errVal, exists := resp["error"]; exists {
			if errMap, ok := errVal.(map[string]interface{}); ok {
				code := fmt.Sprintf("%v", errMap["error_code"])
				if code == "14" {
					sid := fmt.Sprintf("%v", errMap["captcha_sid"])
					redirectUri, _ := errMap["redirect_uri"].(string)

					// Если мы уже пробовали решить и снова получили 14 - значит решение не принято
					if currentCaptchaToken != "" {
						log.Printf("!!! RETRY FAILED. VK still asks for captcha. Response: %s", string(body))
						return nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
					}

					if redirectUri != "" {
						log.Printf("!!! SMART CAPTCHA (SID: %s). AUTO-SOLVING...", sid)
						token, solveErr := solveSmartCaptcha(client, redirectUri)
						if solveErr == nil {
							log.Printf("!!! CAPTCHA AUTO-SOLVED! RETRYING ORIGINAL REQUEST...")
							currentCaptchaToken = token
							currentCaptchaSid = sid
							return doRequest(data, url)
						}
						log.Printf("!!! AUTO-SOLVE FAILED: %v", solveErr)
					}
					return nil, fmt.Errorf("CAPTCHA_WAIT_REQUIRED")
				}
				return nil, fmt.Errorf("VK Error: %v", errMap["error_msg"])
			}
		}
		return resp, nil
	}

	getNestedString := func(m map[string]interface{}, keys ...string) (string, error) {
		var current interface{} = m
		for _, key := range keys {
			if next, ok := current.(map[string]interface{}); ok {
				current = next[key]
			} else {
				return "", fmt.Errorf("key [%s] missing", key)
			}
		}
		if s, ok := current.(string); ok {
			return s, nil
		}
		return "", fmt.Errorf("value not string")
	}

	clientId := "6287487"
	clientSecret := "QbYic1K3lEV5kTGiqlq2"

	resp, err := doRequest(fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", clientId, clientSecret, clientId), "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return "", "", "", err
	}

	token1, err := getNestedString(resp, "data", "access_token")
	if err != nil {
		return "", "", "", fmt.Errorf("step1: %v", err)
	}

	resp, err = doRequest(fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1), fmt.Sprintf("https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=%s", clientId))
	if err != nil {
		return "", "", "", err
	}

	token2, err := getNestedString(resp, "response", "token")
	if err != nil {
		return "", "", "", fmt.Errorf("step2: %v", err)
	}

	resp, err = doRequest(fmt.Sprintf("session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22%s%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA", uuid.New()), "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}

	token3, err := getNestedString(resp, "session_key")
	if err != nil {
		return "", "", "", fmt.Errorf("step3: %v", err)
	}

	resp, err = doRequest(fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3), "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return "", "", "", err
	}

	user, _ := getNestedString(resp, "turn_server", "username")
	pass, _ := getNestedString(resp, "turn_server", "credential")

	var turnAddr string
	if ts, ok := resp["turn_server"].(map[string]interface{}); ok {
		if urls, ok := ts["urls"].([]interface{}); ok && len(urls) > 0 {
			turnAddr, _ = urls[0].(string)
		}
	}

	address := strings.TrimPrefix(strings.TrimPrefix(strings.Split(turnAddr, "?")[0], "turn:"), "turns:")
	return user, pass, address, nil
}

func getYandexCreds(link string) (string, string, string, error) {
	const debug = false
	const telemostConfHost = "cloud-api.yandex.ru"
	telemostConfPath := fmt.Sprintf("%s%s%s", "/telemost_front/v2/telemost/conferences/https%3A%2F%2Ftelemost.yandex.ru%2Fj%2F", link, "/connection?next_gen_media_platform_allowed=false")
	const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0"

	type ConferenceResponse struct {
		URI                 string `json:"uri"`
		RoomID              string `json:"room_id"`
		PeerID              string `json:"peer_id"`
		ClientConfiguration struct {
			MediaServerURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}

	type PartMeta struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
		SendAudio   bool   `json:"sendAudio"`
		SendVideo   bool   `json:"sendVideo"`
	}

	type PartAttrs struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
	}

	type SdkInfo struct {
		Implementation string `json:"implementation"`
		Version        string `json:"version"`
		UserAgent      string `json:"userAgent"`
		HwConcurrency  int    `json:"hwConcurrency"`
	}

	type Capabilities struct {
		OfferAnswerMode             []string `json:"offerAnswerMode"`
		InitialSubscriberOffer      []string `json:"initialSubscriberOffer"`
		SlotsMode                   []string `json:"slotsMode"`
		SimulcastMode               []string `json:"simulcastMode"`
		SelfVadStatus               []string `json:"selfVadStatus"`
		DataChannelSharing          []string `json:"dataChannelSharing"`
		VideoEncoderConfig          []string `json:"videoEncoderConfig"`
		DataChannelVideoCodec       []string `json:"dataChannelVideoCodec"`
		BandwidthLimitationReason   []string `json:"bandwidthLimitationReason"`
		SdkDefaultDeviceManagement  []string `json:"sdkDefaultDeviceManagement"`
		JoinOrderLayout             []string `json:"joinOrderLayout"`
		PinLayout                   []string `json:"pinLayout"`
		SendSelfViewVideoSlot       []string `json:"sendSelfViewVideoSlot"`
		ServerLayoutTransition      []string `json:"serverLayoutTransition"`
		SdkPublisherOptimizeBitrate []string `json:"sdkPublisherOptimizeBitrate"`
		SdkNetworkLostDetection     []string `json:"sdkNetworkLostDetection"`
		SdkNetworkPathMonitor       []string `json:"sdkNetworkPathMonitor"`
		PublisherVp9                []string `json:"publisherVp9"`
		SvcMode                     []string `json:"svcMode"`
		SubscriberOfferAsyncAck     []string `json:"subscriberOfferAsyncAck"`
		SvcModes                    []string `json:"svcModes"`
		ReportTelemetryModes        []string `json:"reportTelemetryModes"`
		KeepDefaultDevicesModes     []string `json:"keepDefaultDevicesModes"`
	}

	type HelloPayload struct {
		ParticipantMeta        PartMeta     `json:"participantMeta"`
		ParticipantAttributes  PartAttrs    `json:"participantAttributes"`
		SendAudio              bool         `json:"sendAudio"`
		SendVideo              bool         `json:"sendVideo"`
		SendSharing            bool         `json:"sendSharing"`
		ParticipantID          string       `json:"participantId"`
		RoomID                 string       `json:"roomId"`
		ServiceName            string       `json:"serviceName"`
		Credentials            string       `json:"credentials"`
		CapabilitiesOffer      Capabilities `json:"capabilitiesOffer"`
		SdkInfo                SdkInfo      `json:"sdkInfo"`
		SdkInitializationID    string       `json:"sdkInitializationId"`
		DisablePublisher       bool         `json:"disablePublisher"`
		DisableSubscriber      bool         `json:"disableSubscriber"`
		DisableSubscriberAudio bool         `json:"disableSubscriberAudio"`
	}

	type HelloRequest struct {
		UID   string       `json:"uid"`
		Hello HelloPayload `json:"hello"`
	}

	type FlexUrls []string

	type WSSResponse struct {
		UID         string `json:"uid"`
		ServerHello struct {
			RtcConfiguration struct {
				IceServers []struct {
					Urls       FlexUrls `json:"urls"`
					Username   string   `json:"username,omitempty"`
					Credential string   `json:"credential,omitempty"`
				} `json:"iceServers"`
			} `json:"rtcConfiguration"`
		} `json:"serverHello"`
	}

	type WSSAck struct {
		Uid string `json:"uid"`
		Ack struct {
			Status struct {
				Code string `json:"code"`
			} `json:"status"`
		} `json:"ack"`
	}

	type WSSData struct {
		ParticipantId string
		RoomId        string
		Credentials   string
		Wss           string
	}

	endpoint := "https://" + telemostConfHost + telemostConfPath
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://telemost.yandex.ru/")
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Client-Instance-Id", uuid.New().String())

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", "", fmt.Errorf("GetConference: status=%s body=%s", resp.Status, string(body))
	}

	var result ConferenceResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", fmt.Errorf("decode conf: %v", err)
	}
	data := WSSData{
		ParticipantId: result.PeerID,
		RoomId:        result.RoomID,
		Credentials:   result.Credentials,
		Wss:           result.ClientConfiguration.MediaServerURL,
	}
	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	h.Set("User-Agent", userAgent)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialer := websocket.Dialer{}
	conn, _, err := dialer.DialContext(ctx, data.Wss, h)
	if err != nil {
		return "", "", "", fmt.Errorf("ws dial: %w", err)
	}
	defer conn.Close()

	req1 := HelloRequest{
		UID: uuid.New().String(),
		Hello: HelloPayload{
			ParticipantMeta: PartMeta{
				Name:        "Гость",
				Role:        "SPEAKER",
				Description: "",
				SendAudio:   false,
				SendVideo:   false,
			},
			ParticipantAttributes: PartAttrs{
				Name:        "Гость",
				Role:        "SPEAKER",
				Description: "",
			},
			SendAudio:   false,
			SendVideo:   false,
			SendSharing: false,

			ParticipantID: data.ParticipantId,
			RoomID:        data.RoomId,
			ServiceName:   "telemost",
			Credentials:   data.Credentials,
			SdkInfo: SdkInfo{
				Implementation: "browser",
				Version:        "5.15.0",
				UserAgent:      userAgent,
				HwConcurrency:  4,
			},
			SdkInitializationID:    uuid.New().String(),
			DisablePublisher:       false,
			DisableSubscriber:      false,
			DisableSubscriberAudio: false,
			CapabilitiesOffer: Capabilities{
				OfferAnswerMode:             []string{"SEPARATE"},
				InitialSubscriberOffer:      []string{"ON_HELLO"},
				SlotsMode:                   []string{"FROM_CONTROLLER"},
				SimulcastMode:               []string{"DISABLED"},
				SelfVadStatus:               []string{"FROM_SERVER"},
				DataChannelSharing:          []string{"TO_RTP"},
				VideoEncoderConfig:          []string{"NO_CONFIG"},
				DataChannelVideoCodec:       []string{"VP8"},
				BandwidthLimitationReason:   []string{"BANDWIDTH_REASON_DISABLED"},
				SdkDefaultDeviceManagement:  []string{"SDK_DEFAULT_DEVICE_MANAGEMENT_DISABLED"},
				JoinOrderLayout:             []string{"JOIN_ORDER_LAYOUT_DISABLED"},
				PinLayout:                   []string{"PIN_LAYOUT_DISABLED"},
				SendSelfViewVideoSlot:       []string{"SEND_SELF_VIEW_VIDEO_SLOT_DISABLED"},
				ServerLayoutTransition:      []string{"SERVER_LAYOUT_TRANSITION_DISABLED"},
				SdkPublisherOptimizeBitrate: []string{"SDK_PUBLISHER_OPTIMIZE_BITRATE_DISABLED"},
				SdkNetworkLostDetection:     []string{"SDK_NETWORK_LOST_DETECTION_DISABLED"},
				SdkNetworkPathMonitor:       []string{"SDK_NETWORK_PATH_MONITOR_DISABLED"},
				PublisherVp9:                []string{"PUBLISH_VP9_DISABLED"},
				SvcMode:                     []string{"SVC_MODE_DISABLED"},
				SubscriberOfferAsyncAck:     []string{"SUBSCRIBER_OFFER_ASYNC_ACK_DISABLED"},
				SvcModes:                    []string{"FALSE"},
				ReportTelemetryModes:        []string{"TRUE"},
				KeepDefaultDevicesModes:     []string{"TRUE"},
			},
		},
	}

	if debug {
		b, _ := json.MarshalIndent(req1, "", "  ")
		log.Printf("Sending HELLO:\n%s", string(b))
	}

	if err := conn.WriteJSON(req1); err != nil {
		return "", "", "", fmt.Errorf("ws write: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return "", "", "", fmt.Errorf("ws read: %w", err)
		}
		if debug {
			s := string(msg)
			if len(s) > 800 {
				s = s[:800] + "...(truncated)"
			}
			log.Printf("WSS recv: %s", s)
		}

		var ack WSSAck
		if err := json.Unmarshal(msg, &ack); err == nil && ack.Ack.Status.Code != "" {
			continue
		}

		var resp WSSResponse
		if err := json.Unmarshal(msg, &resp); err == nil {
			ice := resp.ServerHello.RtcConfiguration.IceServers
			for _, s := range ice {
				for _, u := range s.Urls {
					if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
						continue
					}
					if strings.Contains(u, "transport=tcp") {
						continue
					}
					clean := strings.Split(u, "?")[0]
					address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

					return s.Username, s.Credential, address, nil
				}
			}
		}
	}
}

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Client(conn, peer, config)
	if err != nil {
		return nil, err
	}

	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}

func oneDtlsConnection(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, c chan<- error, sessionID []byte, streamID byte) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error = nil
	defer func() { c <- err }()
	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()
	var conn1, conn2 net.PacketConn
	conn1, conn2 = connutil.AsyncPacketPipe()
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case connchan <- conn2:
			}
		}
	}()
	dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, peer)
	if err1 != nil {
		err = fmt.Errorf("failed to connect DTLS: %s", err1)
		return
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close DTLS connection: %s", closeErr)
			return
		}
		log.Printf("Closed DTLS connection\n")
	}()

	// Phase 1: Send Session ID + Stream ID (17 bytes)
	dtlsConn.SetWriteDeadline(time.Now().Add(time.Second * 5))
	idBuf := make([]byte, 17)
	copy(idBuf[:16], sessionID)
	idBuf[16] = streamID
	if _, err1 = dtlsConn.Write(idBuf); err1 != nil {
		err = fmt.Errorf("failed to send session ID: %s", err1)
		return
	}

	log.Printf("Established DTLS connection and sent session ID with stream %d!\n", streamID)
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case okchan <- struct{}{}:
			}
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(2)
	context.AfterFunc(dtlsctx, func() {
		listenConn.SetDeadline(time.Now())
		dtlsConn.SetDeadline(time.Now())
	})
	var addr atomic.Value
	// Start read-loop on listenConn
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, addr1, err1 := listenConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = dtlsConn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	// Start read-loop on dtlsConn
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				log.Printf("Failed: no listener ip")
				return
			}

			_, err1 = listenConn.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	wg.Wait()
	listenConn.SetDeadline(time.Time{})
	dtlsConn.SetDeadline(time.Time{})
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type turnParams struct {
	host     string
	port     string
	link     string
	udp      bool
	getCreds getCredsFunc
}

func oneTurnConnection(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, c chan<- error) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error = nil
	defer func() { c <- err }()
	user, pass, url, err1 := turnParams.getCreds(turnParams.link)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		return
	}
	urlhost, urlport, err1 := net.SplitHostPort(url)
	if err1 != nil {
		err = fmt.Errorf("failed to parse TURN server address: %s", err1)
		return
	}
	if turnParams.host != "" {
		urlhost = turnParams.host
	}
	if turnParams.port != "" {
		urlport = turnParams.port
	}
	var turnServerAddr string
	turnServerAddr = net.JoinHostPort(urlhost, urlport)
	turnServerUdpAddr, err1 := net.ResolveUDPAddr("udp", turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %s", err1)
		return
	}
	turnServerAddr = turnServerUdpAddr.String()
	fmt.Println(turnServerUdpAddr.IP)
	// Dial TURN Server
	var cfg *turn.ClientConfig
	var turnConn net.PacketConn
	var d net.Dialer
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if turnParams.udp {
		conn, err2 := net.DialUDP("udp", nil, turnServerUdpAddr) // nolint: noctx
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = &connectedUDPConn{conn}
	} else {
		conn, err2 := d.DialContext(ctx1, "tcp", turnServerAddr) // nolint: noctx
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = turn.NewSTUNConn(conn)
	}
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}
	// Start a new TURN Client and wrap our net.Conn in a STUNConn
	// This allows us to simulate datagram based communication over a net.Conn
	cfg = &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}

	client, err1 := turn.NewClient(cfg)
	if err1 != nil {
		err = fmt.Errorf("failed to create TURN client: %s", err1)
		return
	}
	defer client.Close()

	// Start listening on the conn provided.
	err1 = client.Listen()
	if err1 != nil {
		err = fmt.Errorf("failed to listen: %s", err1)
		return
	}

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = fmt.Errorf("failed to allocate: %s", err1)
		return
	}
	defer func() {
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
		}
	}()

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(context.Background())
	context.AfterFunc(turnctx, func() {
		relayConn.SetDeadline(time.Now())
		conn2.SetDeadline(time.Now())
	})
	var addr atomic.Value
	// Start read-loop on conn2 (output of DTLS)
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, addr1, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = relayConn.WriteTo(buf[:n], peer)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	// Start read-loop on relayConn
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				log.Printf("Failed: no listener ip")
				return
			}

			_, err1 = conn2.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	wg.Wait()
	relayConn.SetDeadline(time.Time{})
	conn2.SetDeadline(time.Time{})
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, listenConnChan <-chan net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, sessionID []byte, streamID byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case listenConn := <-listenConnChan:
			c := make(chan error)
			go oneDtlsConnection(ctx, peer, listenConn, connchan, okchan, c, sessionID, streamID)
			if err := <-c; err != nil {
				log.Printf("%s", err)
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
				c := make(chan error)
				go oneTurnConnection(ctx, turnParams, peer, conn2, c)
				if err := <-c; err != nil {
					log.Printf("%s", err)
				}
			default:
			}
		}
	}
}

func main() { //nolint:cyclop
	rand.Seed(time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		select {
		case <-signalChan:
		case <-time.After(5 * time.Second):
		}
		log.Fatalf("Exit...\n")
	}()

	host := flag.String("turn", "", "override TURN server ip")
	port := flag.String("port", "", "override TURN port")
	listen := flag.String("listen", "127.0.0.1:9000", "listen on ip:port")
	vklink := flag.String("vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	yalink := flag.String("yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	peerAddr := flag.String("peer", "", "peer server address (host:port)")
	n := flag.Int("n", 0, "connections to TURN (default 16 for VK, 1 for Yandex)")
	udp := flag.Bool("udp", false, "connect to TURN with UDP")
	direct := flag.Bool("no-dtls", false, "connect without obfuscation. DO NOT USE")
	sessionIDFlag := flag.String("session-id", "", "override session ID (hex, 32 chars)")
	flag.Parse()
	if *peerAddr == "" {
		log.Panicf("Need peer address!")
	}
	peer, err := net.ResolveUDPAddr("udp", *peerAddr)
	if err != nil {
		panic(err)
	}
	if (*vklink == "") == (*yalink == "") {
		log.Panicf("Need either vk-link or yandex-link!")
	}
	var link string
	var getCreds getCredsFunc
	if *vklink != "" {
		parts := strings.Split(*vklink, "join/")
		link = parts[len(parts)-1]
		dialer := dnsdialer.New(
			dnsdialer.WithResolvers("77.88.8.8:53", "77.88.8.1:53", "8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53"),
			dnsdialer.WithStrategy(dnsdialer.Fallback{}),
			dnsdialer.WithCache(100, 10*time.Hour, 10*time.Hour),
		)
		getCreds = func(s string) (string, string, string, error) {
			return getVkCreds(s, dialer)
		}
		if *n <= 0 {
			*n = 16
		}
	} else {
		parts := strings.Split(*yalink, "j/")
		link = parts[len(parts)-1]
		getCreds = getYandexCreds
		if *n <= 0 {
			*n = 1
		}
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}
	params := &turnParams{
		*host,
		*port,
		link,
		*udp,
		getCreds,
	}

	var sessionID []byte
	if *sessionIDFlag != "" {
		sessionID = make([]byte, 16)
		if _, err := fmt.Sscanf(*sessionIDFlag, "%x", &sessionID); err != nil {
			log.Panicf("Invalid session ID: %v", err)
		}
	} else {
		sessionID, _ = uuid.New().MarshalBinary()
	}
	log.Printf("Session ID: %x", sessionID)

	listenConnChan := make(chan net.PacketConn)
	listenConn, err := net.ListenPacket("udp", *listen) // nolint: noctx
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Panicf("Failed to close local connection: %s", closeErr)
		}
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenConnChan <- listenConn:
			}
		}
	}()

	wg1 := sync.WaitGroup{}
	t := time.Tick(100 * time.Millisecond)
	if *direct {
		for i := 0; i < *n; i++ {
			wg1.Add(1)
			go func() {
				defer wg1.Done()
				oneTurnConnectionLoop(ctx, params, peer, listenConnChan, t)
			}()
		}
	} else {
		okchan := make(chan struct{})
		connchan := make(chan net.PacketConn)

		wg1.Add(1)
		go func() {
			defer wg1.Done()
			oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, okchan, sessionID, 0)
		}()

		wg1.Add(1)
		go func() {
			defer wg1.Done()
			oneTurnConnectionLoop(ctx, params, peer, connchan, t)
		}()

		select {
		case <-okchan:
		case <-ctx.Done():
		}
		for i := 0; i < *n-1; i++ {
			delay := 5 + rand.Intn(16)
			select {
			case <-time.After(time.Duration(delay) * time.Second):
			case <-ctx.Done():
				return
			}
			connchan := make(chan net.PacketConn)
			wg1.Add(1)
			go func(streamID byte) {
				defer wg1.Done()
				oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, nil, sessionID, streamID)
			}(byte(i + 1))
			wg1.Add(1)
			go func() {
				defer wg1.Done()
				oneTurnConnectionLoop(ctx, params, peer, connchan, t)
			}()
		}
	}

	wg1.Wait()
}
