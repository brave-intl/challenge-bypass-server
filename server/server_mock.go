package server

import (
	"context"
	"net/http"

	"github.com/brave-intl/bat-go/libs/handlers"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/model"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

type MockServer struct {
	mock.Mock
}

func (m *MockServer) InitDBConfig() error {
	ret := m.Called()
	return ret.Error(0)
}

func (m *MockServer) ListenAndServe(a context.Context, b *logrus.Logger) error {
	ret := m.Called(a, b)
	return ret.Error(0)
}

func (m *MockServer) LoadDBConfig(a DBConfig) {
	m.Called(a)
}

func (m *MockServer) InitDB() {
	m.Called()
}

func (m *MockServer) FetchAllIssuers() (*[]model.Issuer, error) {
	ret := m.Called()
	return ret.Get(0).(*[]model.Issuer), ret.Error(1)
}

func (m *MockServer) RotateIssuersV3() error {
	ret := m.Called()
	return ret.Error(0)
}

func (m *MockServer) RedeemToken(a *model.Issuer, b *crypto.TokenPreimage, c string, d int64) error {
	ret := m.Called(a, b, c, d)
	return ret.Error(0)
}

func (m *MockServer) SetupCronTasks() {
	m.Called()
}

func (m *MockServer) InitDynamo() {
	m.Called()
}

func (m *MockServer) PersistRedemption(RedemptionV2) error {
	ret := m.Called()
	return ret.Error(0)
}

func (m *MockServer) CheckRedeemedTokenEquivalence(a *model.Issuer, b *crypto.TokenPreimage, c string, d int64) (*RedemptionV2, Equivalence, error) {
	ret := m.Called()
	return ret.Get(0).(*RedemptionV2), ret.Get(1).(Equivalence), ret.Error(2)
}

func (m *MockServer) GetLatestIssuer(a string, b int16) (*model.Issuer, *handlers.AppError) {
	ret := m.Called(a, b)
	return ret.Get(0).(*model.Issuer), ret.Get(1).(*handlers.AppError)
}

func (m *MockServer) GetLatestIssuerKafka(a string, b int16) (*model.Issuer, error) {
	ret := m.Called(a, b)
	return ret.Get(0).(*model.Issuer), ret.Error(1)
}

func (m *MockServer) GetIssuers(a string) ([]model.Issuer, error) {
	ret := m.Called(a)
	return ret.Get(0).([]model.Issuer), ret.Error(1)
}

func (m *MockServer) BlindedTokenIssuerHandlerV2(a http.ResponseWriter, b *http.Request) *handlers.AppError {
	ret := m.Called(a, b)
	return ret.Get(0).(*handlers.AppError)
}
