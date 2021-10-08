package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Sora8d/bookstore_oauth-go/oauth/util/errors"
	rest "github.com/go-resty/resty/v2"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-User-Id"

	paramAccessToken = "access_token"
)

var oauthRestClient *rest.Client = rest.New()

func init() {
	oauthRestClient.SetHostURL("http://127.0.0.1:8080")
	oauthRestClient.SetTimeout(100 * time.Millisecond)
}

type oauthClient struct{}

type oauthInterface interface {
}

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(at_string string) (*accessToken, *errors.RestErr) {
	restreq := oauthRestClient.R()
	restreq.Method = http.MethodGet
	restreq.URL = fmt.Sprintf("/oauth/access_token/%s", at_string)

	response, err := restreq.Send()
	if err != nil {
		return nil, errors.NewInternalServerError("error in the restclient functionality")
	}
	if response == nil || response.Body() == nil {
		return nil, errors.NewInternalServerError("invalid restclient response when trying to login user")
	}
	if response.IsError() {
		var restErr errors.RestErr
		err := json.Unmarshal(response.Body(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to log into user")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Body(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal acces token response")
	}
	return &at, nil
}
