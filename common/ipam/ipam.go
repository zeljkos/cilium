//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package ipam

import (
	"net"
	"sync"

	hb "github.com/containernetworking/cni/plugins/ipam/host-local/backend"
	lnAPI "github.com/docker/libnetwork/ipams/remote/api"
	lnTypes "github.com/docker/libnetwork/types"
	"k8s.io/kubernetes/pkg/registry/service/ipallocator"
)

type IPAMType string

const (
	// CNIIPAMType
	CNIIPAMType IPAMType = "cni-host-local"
	// LibnetworkIPAMType
	LibnetworkIPAMType IPAMType = "libnetwork"

	// LibnetworkDefaultPoolV4 is the IPv4 pool name for libnetwork.
	LibnetworkDefaultPoolV4 = "CiliumPoolv4"
	// LibnetworkDefaultPoolV6 is the IPv6 pool name for libnetwork.
	LibnetworkDefaultPoolV6 = "CiliumPoolv6"
	// LibnetworkDummyV4AllocPool is never exposed, makes libnetwork happy.
	LibnetworkDummyV4AllocPool = "0.0.0.0/0"
	// LibnetworkDummyV4Gateway is never exposed, makes libnetwork happy.
	LibnetworkDummyV4Gateway = "1.1.1.1/32"
)

// IPAMConfig is the IPAM configuration used for a particular IPAM type.
type IPAMConfig struct {
	IPAMConfig     hb.IPAMConfig
	IPv6Allocator  *ipallocator.Range
	IPv4Allocator  *ipallocator.Range
	AllocatorMutex sync.Mutex
}

// IPAMReq is used for IPAM request operation.
type IPAMReq struct {
	ContainerID           string                       `json:",omitempty"`
	IP                    *net.IP                      `json:",omitempty"`
	RequestPoolRequest    *lnAPI.RequestPoolRequest    `json:",omitempty"`
	RequestAddressRequest *lnAPI.RequestAddressRequest `json:",omitempty"`
	ReleaseAddressRequest *lnAPI.ReleaseAddressRequest `json:",omitempty"`
}

// IPAMConfigRep is used for IPAM configuration reply messages.
type IPAMConfigRep struct {
	RequestPoolResponse *lnAPI.RequestPoolResponse `json:",omitempty"`
	IPAMConfig          *IPAMRep                   `json:",omitempty"`
}

// IPAMRep contains both IPv4 and IPv6 IPAM configuration.
type IPAMRep struct {
	// IPv6 configuration.
	IP6 *IPConfig
	// IPv4 configuration.
	IP4 *IPConfig
}

// IPConfig is our network representation of an IP configuration.
type IPConfig struct {
	// Gateway for this IP configuration.
	Gateway net.IP
	// IP of the configuration.
	IP net.IPNet
	// Routes for this IP configuration.
	Routes []Route
}

// Route is the routing representation of an IPConfig. It can be a L2 or L3 route
// depending if NextHop is nil or not.
type Route struct {
	Destination net.IPNet
	NextHop     net.IP
	Type        int
}

// Sort an array of routes by mask, narrow first
type ByMask []Route

func (a ByMask) Len() int {
	return len(a)
}

func (a ByMask) Less(i, j int) bool {
	len_a, _ := a[i].Destination.Mask.Size()
	len_b, _ := a[j].Destination.Mask.Size()
	return len_a > len_b
}

func (a ByMask) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// NewRoute returns a Route from dst and nextHop with the proper libnetwork type based on
// NextHop being nil or not.
func NewRoute(dst net.IPNet, nextHop net.IP) *Route {
	ciliumRoute := &Route{
		Destination: dst,
		NextHop:     nextHop,
	}
	if nextHop == nil {
		ciliumRoute.Type = lnTypes.CONNECTED
	} else {
		ciliumRoute.Type = lnTypes.NEXTHOP
	}
	return ciliumRoute
}

// IsL2 returns true if the route represents a L2 route and false otherwise.
func (r *Route) IsL2() bool {
	return r.NextHop == nil
}

// IsL3 returns true if the route represents a L3 route and false otherwise.
func (r *Route) IsL3() bool {
	return r.NextHop != nil
}
