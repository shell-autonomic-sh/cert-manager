/*
Copyright 2018 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cfssl

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kubeinformers "k8s.io/client-go/informers"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

const (
	issuerName                = "test-cfssl-certs-issuer"
	issuerNamespace           = "test-namespace"
	tlsSecretName             = "test-secret-tls"
	authKeySecretName         = "test-auth-key"
	validAuthKeySecretValue   = "deadbeef"
	invalidAuthKeySecretValue = "fooobaar"
	certStr                   = "----BEGIN CERTIFICATE----blah blah blah-----END CERTIFICATE-----"
)

type testT struct {
	algorithm        v1alpha1.KeyAlgorithm
	expectedCrt      string
	expectedRespBody string
	expectedErrStr   string
	authKeySecret    *corev1.Secret
	tlsSecret        *corev1.Secret
	serverPath       string
	serverStatusCode int
	profile          string
	label            string
}

func TestCFSSLIssue(t *testing.T) {
	errorTests := map[string]*testT{
		"fails when authkey secret is not a valid hexadecimal string": &testT{
			authKeySecret:  newSecret(authKeySecretName, "auth-key", invalidAuthKeySecretValue),
			algorithm:      v1alpha1.ECDSAKeyAlgorithm,
			expectedErrStr: messageAuthKeyFormat,
			serverPath:     "/v1/certs/sign",
		},
		"fails when remote cfssl server response is not success": &testT{
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":false,"result":{"certificate":"%s"}}`, certStr),
			expectedErrStr:   messageRemoteServerResponseNotSuccess,
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"fails when remote cfssl server response status is not 200": &testT{
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":false,"result":{"certificate":"%s"}}`, certStr),
			expectedErrStr:   messageRemoteServerResponseNon2xx,
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusBadRequest,
		},
	}

	successTests := map[string]*testT{
		"for new certificates, issues ecdsa based certs when authkey is provided": &testT{
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"for new certificates, issues rsa based certs when authkey is provided": &testT{
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"for new certificates, issues ecdsa based certs when authkey is not provided": &testT{
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"for new certificates, issues rsa based certs when authkey is not provided": &testT{
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"for existing certificate, issues ecdsa based certs when authkey is provided": &testT{
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			tlsSecret:        newTLSSecret(t, tlsSecretName, v1alpha1.ECDSAKeyAlgorithm),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"for existing certificates, issues rsa based certs when authkey is provided": &testT{
			authKeySecret:    newSecret(authKeySecretName, "auth-key", validAuthKeySecretValue),
			tlsSecret:        newTLSSecret(t, tlsSecretName, v1alpha1.RSAKeyAlgorithm),
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"for existing certificates, issues ecdsa based certs when authkey is not provided": &testT{
			tlsSecret:        newTLSSecret(t, tlsSecretName, v1alpha1.ECDSAKeyAlgorithm),
			algorithm:        v1alpha1.ECDSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"for existing certificates, issues rsa based certs when authkey is not provided": &testT{
			tlsSecret:        newTLSSecret(t, tlsSecretName, v1alpha1.RSAKeyAlgorithm),
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
		"sends the label & profile provided on the certificate with the server request": &testT{
			algorithm:        v1alpha1.RSAKeyAlgorithm,
			profile:          "blah-profile",
			label:            "blah-label",
			expectedCrt:      certStr,
			expectedRespBody: fmt.Sprintf(`{"success":true,"result":{"certificate":"%s"}}`, certStr),
			serverPath:       "/v1/certs/sign",
			serverStatusCode: http.StatusOK,
		},
	}

	for msg, test := range errorTests {
		t.Run(msg, func(t *testing.T) {
			server := testCFSSLServer(test.expectedRespBody, test.serverStatusCode, test.profile, test.label)

			certificate := newCertificate(test.algorithm, test.profile, test.label)
			issuer, err := newIssuer(test.authKeySecret, test.tlsSecret, server.URL, test.serverPath)
			if err != nil {
				t.Fatalf(err.Error())
			}

			_, _, err = issuer.Issue(context.TODO(), certificate)
			if err == nil {
				t.Fatalf("expected error to occur: %s", err)
			}

			if !strings.Contains(strings.ToLower(err.Error()), test.expectedErrStr) {
				t.Fatalf(`expected err: "%s" to contain: "%s"`, err.Error(), test.expectedErrStr)
			}
		})
	}

	for msg, test := range successTests {
		t.Run(msg, func(t *testing.T) {
			server := testCFSSLServer(test.expectedRespBody, test.serverStatusCode, test.profile, test.label)

			certificate := newCertificate(test.algorithm, test.profile, test.label)
			issuer, err := newIssuer(test.authKeySecret, test.tlsSecret, server.URL, test.serverPath)
			if err != nil {
				t.Fatalf(err.Error())
			}

			_, certPem, err := issuer.Issue(context.TODO(), certificate)
			if err != nil {
				t.Fatalf(err.Error())
			}

			if string(certPem) != test.expectedCrt {
				t.Fatalf(`expected "%s", got "%s"`, test.expectedCrt, certPem)
			}
		})
	}
}

func newCertificate(keyAlgo v1alpha1.KeyAlgorithm, profile, label string) *v1alpha1.Certificate {
	config := &v1alpha1.CFSSLCertificateConfig{}
	if len(profile) > 0 {
		config.Profile = profile
	}

	if len(label) > 0 {
		config.Label = label
	}

	return &v1alpha1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("test-%s-certificate", keyAlgo),
			Namespace: issuerNamespace,
		},
		Spec: v1alpha1.CertificateSpec{
			SecretName: tlsSecretName,
			IssuerRef: v1alpha1.ObjectReference{
				Name: issuerName,
			},
			CommonName:   "test.domain",
			DNSNames:     []string{"test.other.domain"},
			KeyAlgorithm: keyAlgo,
			CFSSL:        config,
		},
	}
}

func newIssuer(authKeySecret, tlsSecret *corev1.Secret, serverURL, serverPath string) (issuer.Interface, error) {
	cfsslIssuer := &v1alpha1.CFSSLIssuer{
		Server: serverURL,
		Path:   serverPath,
	}

	client := kubefake.NewSimpleClientset()
	sharedInformerFactory := kubeinformers.NewSharedInformerFactory(client, 0)
	stopCh := make(chan struct{})
	defer close(stopCh)

	if authKeySecret != nil {
		cfsslIssuer.AuthKey = &v1alpha1.SecretKeySelector{
			LocalObjectReference: v1alpha1.LocalObjectReference{Name: authKeySecretName},
			Key:                  "auth-key",
		}

		sharedInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(authKeySecret)
	}

	if tlsSecret != nil {
		sharedInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(tlsSecret)
	}

	ctx := &controller.Context{
		Client: client,
		KubeSharedInformerFactory: sharedInformerFactory,
		IssuerOptions:             controller.IssuerOptions{},
	}

	issuer := &v1alpha1.Issuer{
		TypeMeta: metav1.TypeMeta{
			Kind: "Issuer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      issuerName,
			Namespace: issuerNamespace,
		},
		Spec: v1alpha1.IssuerSpec{
			IssuerConfig: v1alpha1.IssuerConfig{
				CFSSL: cfsslIssuer,
			},
		},
	}

	sharedInformerFactory.Start(stopCh)
	return NewCFSSL(ctx, issuer)
}

func testCFSSLServer(respBody string, statusCode int, profile, label string) *httptest.Server {
	var resp string
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if statusCode != http.StatusOK {
			http.Error(w, "not found", statusCode)
			return
		}

		requestBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "error reading request body.", http.StatusInternalServerError)
			return
		}

		switch r.RequestURI {
		case "/v1/certs/sign":
			var request UnauthenticatedRequest

			err := json.Unmarshal(requestBody, &request)
			if err != nil {
				http.Error(w, "error unmarshalling request body.", http.StatusBadRequest)
				return
			}

			if request.Label != label {
				http.Error(w, fmt.Sprintf("expected label '%s', but got '%s'.", label, request.Label), http.StatusBadRequest)
				return
			}

			if request.Profile != profile {
				http.Error(w, fmt.Sprintf("expected profile '%s', but got '%s'.", profile, request.Profile), http.StatusBadRequest)
				return
			}

			resp = respBody
		case "/v1/certs/authsign":
			resp = respBody
		default:
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Write([]byte(resp))
	}))
}

func newSecret(name, key, value string) *corev1.Secret {
	data := make(map[string][]byte)
	data[key] = []byte(value)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: issuerNamespace,
		},
		Data: data,
	}
}

func newTLSSecret(t *testing.T, name string, keyAlgorithm v1alpha1.KeyAlgorithm) *corev1.Secret {
	cert := newCertificate(keyAlgorithm, "", "")
	privateKey, err := pki.GeneratePrivateKeyForCertificate(cert)
	if err != nil {
		t.Fatalf(err.Error())
	}

	privateKeyBytes, err := pki.EncodePrivateKey(privateKey)
	if err != nil {
		t.Fatalf(err.Error())
	}

	return newSecret(name, "tls.key", string(privateKeyBytes))
}
