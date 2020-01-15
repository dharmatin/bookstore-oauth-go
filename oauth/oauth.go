package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/dharmatin/bookstore-oauth-go/oauth/errors"
	"github.com/mercadolibre/golang-restclient/rest"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic        = "X-Public"
	headerXClientID      = "X-Client-Id"
	headerXCallerID      = "X-Caller-Id"
	parameterAccessToken = "access_token"
)

var (
	oauthAcessTokenClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8083",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

func isPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func Auth(request *http.Request) *errors.RestError {
	if request == nil {
		return nil
	}
	cleanRequest(request)
	accessToken := strings.TrimSpace(request.URL.Query().Get(parameterAccessToken))
	if accessToken == "" {
		return nil
	}
	at, err := getAccessToken(accessToken)
	if err != nil {
		return err
	}
	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

func cleanRequest(r *http.Request) {
	if r == nil {
		return
	}
	r.Header.Del(headerXClientID)
	r.Header.Del(headerXCallerID)
}

func getAccessToken(token string) (*accessToken, *errors.RestError) {
	response := oauthAcessTokenClient.Get(fmt.Sprintf("/oauth/access_token/%s", token))
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("error when request to login api")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestError
		err := json.Unmarshal(response.Bytes(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when login")
		}
		return nil, &restErr
	}
	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when unmarshaling")
	}
	return &at, nil
}
