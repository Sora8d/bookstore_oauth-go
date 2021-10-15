package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Sora8d/bookstore_utils-go/rest_errors"
	rest "github.com/go-resty/resty/v2"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-User-Id"
	headerXAdmin    = "X-Admin"

	paramAccessToken = "access_token"
)

var OauthRestClient oauthInterface = &oauthClient{}

type oauthClient struct {
	client *rest.Client
}

type oauthInterface interface {
	SetClient(string)
	getAccessToken(string) (*accessToken, rest_errors.RestErr)
	GetClient() *http.Client
}

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
	Admin    bool   `json:"permissions"`
}

func (oac *oauthClient) GetClient() *http.Client {
	return oac.client.GetClient()
}

func (oac *oauthClient) SetClient(oauthUrl string) {
	oac.client = rest.New()
	oac.client.SetHostURL(oauthUrl)
	oac.client.SetTimeout(100 * time.Millisecond)
}

func (oac *oauthClient) getAccessToken(at_string string) (*accessToken, rest_errors.RestErr) {
	restreq := oac.client.R()
	restreq.Method = http.MethodGet
	restreq.URL = fmt.Sprintf("/oauth/access_token/%s", at_string)

	response, err := restreq.Send()
	if err != nil {
		resterr := rest_errors.NewInternalServerError("error in the restclient functionality", err)
		return nil, resterr
	}
	if response == nil || response.Body() == nil {
		resterr := rest_errors.NewInternalServerError("invalid restclient response when trying to login user", errors.New("response nil"))
		return nil, resterr
	}
	if response.IsError() {
		var restErr rest_errors.RestErr
		restErr, err = rest_errors.NewRestErrorFromBytes(response.Body())
		if err != nil {
			resterr := rest_errors.NewInternalServerError("invalid error interface when trying to log into user", err)
			return nil, resterr
		}
		return nil, restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Body(), &at); err != nil {
		resterr := rest_errors.NewInternalServerError("error when trying to unmarshal access token response", err)
		return nil, resterr
	}
	return &at, nil
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

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := oauthRestClient.getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	request.Header.Add(headerXAdmin, fmt.Sprintf("%v", at.Admin))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
	request.Header.Del(headerXAdmin)
}
