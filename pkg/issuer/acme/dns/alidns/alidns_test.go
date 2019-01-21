package alidns

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	// "github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

var (
	alidnsLiveTest  bool
	alidnsAccessKey string
	alidnsSecretKey string
	alidnsRegion    string
	alidnsDomain    string
)

// var envTest = tester.NewEnvTest(
// 	"ALICLOUD_ACCESS_KEY",
// 	"ALICLOUD_SECRET_KEY").
// 	WithDomain("ALICLOUD_DOMAIN")

func init() {
	alidnsAccessKey = os.Getenv("ALICLOUD_ACCESS_KEY")
	alidnsSecretKey = os.Getenv("ALICLOUD_SECRET_KEY")
	alidnsRegion = os.Getenv("ALICLOUD_REGION")
	alidnsDomain = os.Getenv("ALICLOUD_DOMAIN")
	if len(alidnsAccessKey) > 0 && len(alidnsSecretKey) > 0 && len(alidnsRegion) > 0 {
		alidnsLiveTest = true
	}
}

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				"ALICLOUD_ACCESS_KEY": "123",
				"ALICLOUD_SECRET_KEY": "456",
			},
		},
		{
			desc: "missing credentials",
			envVars: map[string]string{
				"ALICLOUD_ACCESS_KEY": "",
				"ALICLOUD_SECRET_KEY": "",
			},
			expected: "alicloud: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			// defer envTest.RestoreEnv()
			// envTest.ClearEnv()

			for k, v := range test.envVars {
				os.Setenv(k, v)
			}

			// envTest.Apply(test.envVars)

			p, err := NewDNSProvider()

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.client)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc      string
		apiKey    string
		secretKey string
		expected  string
	}{
		{
			desc:      "success",
			apiKey:    "123",
			secretKey: "456",
		},
		{
			desc:     "missing credentials",
			expected: "alicloud: credentials missing",
		},
		{
			desc:      "missing api key",
			secretKey: "456",
			expected:  "alicloud: credentials missing",
		},
		{
			desc:     "missing secret key",
			apiKey:   "123",
			expected: "alicloud: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.APIKey = test.apiKey
			config.SecretKey = test.secretKey

			p, err := NewDNSProviderConfig(config)

			if len(test.expected) == 0 {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.client)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestLivePresent(t *testing.T) {
	if !alidnsLiveTest {
		t.Skip("skipping live test")
	}

	os.Setenv("ALICLOUD_ACCESS_KEY", alidnsAccessKey)
	os.Setenv("ALICLOUD_SECRET_KEY", alidnsSecretKey)
	os.Setenv("ALICLOUD_REGION", alidnsRegion)

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.Present(alidnsDomain, "", "123d==")
	require.NoError(t, err)
}

func TestLiveCleanUp(t *testing.T) {
	if !alidnsLiveTest {
		t.Skip("skipping live test")
	}

	os.Setenv("ALICLOUD_ACCESS_KEY", alidnsAccessKey)
	os.Setenv("ALICLOUD_SECRET_KEY", alidnsSecretKey)
	os.Setenv("ALICLOUD_REGION", alidnsRegion)

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	time.Sleep(1 * time.Second)

	err = provider.CleanUp(alidnsDomain, "", "123d==")
	require.NoError(t, err)
}
