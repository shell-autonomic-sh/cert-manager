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
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/controller"
	"github.com/jetstack/cert-manager/pkg/issuer"
)

// CFSSL allows communicating with a remote cfssl based certificate authority.
// A secret resource is used to store the authkey that is used to make authenticated requests to the remote CA server.
type CFSSL struct {
	*controller.Context
	issuer        v1alpha1.GenericIssuer
	secretsLister corelisters.SecretLister

	// Namespace in which to read resources related to this Issuer from.
	// For Issuers, this will be the namespace of the Issuer.
	// For ClusterIssuers, this will be the cluster resource namespace.
	resourceNamespace string
}

// Request represents a CFSSL request which can either be authenticated or unauthenticated.
type Request interface{}

// Response defines the response body received from a remote cfssl ca server
type Response struct {
	Success bool                     `json:"success"`
	Result  map[string]interface{}   `json:"result"`
	Errors  []map[string]interface{} `json:"errors"`
}

// UnauthenticatedRequest defines the body of an unauthenticated request to send to a remote cfssl ca server
type UnauthenticatedRequest struct {
	Profile            string `json:"profile,omitempty"`
	Label              string `json:"label,omitempty"`
	CertificateRequest string `json:"certificate_request"`
}

// AuthenticatedRequest defines the body of an authenticated request to send to a remote cfssl ca server
type AuthenticatedRequest struct {
	Token   string `json:"token"`
	Request string `json:"request"`
}

// NewCFSSL initializes a new CFSSL struct and returns a pointer to it
func NewCFSSL(ctx *controller.Context, issuer v1alpha1.GenericIssuer) (issuer.Interface, error) {
	secretsLister := ctx.KubeSharedInformerFactory.Core().V1().Secrets().Lister()

	return &CFSSL{
		Context:           ctx,
		issuer:            issuer,
		secretsLister:     secretsLister,
		resourceNamespace: ctx.IssuerOptions.ResourceNamespace(issuer),
	}, nil
}

// Register CFSSL Issuer with the issuer factory
func init() {
	controller.RegisterIssuer(controller.IssuerCFSSL, NewCFSSL)
}
