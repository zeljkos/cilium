u#!/ave ./...r/bin/env bash
set -e
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../../hack/vendor-utils.sh"

clean_dir "${dir}"

vendor_dir="${dir}/vendor"

#cd "${vendor_dir}"
#clone git github.com/docker/libnetwork
#cd "${vendor_dir}/github.com/docker/libnetwork"
#git fetch origin pull/826/head:ipv6-citizen
#git checkout ipv6-citizen

cd "${vendor_dir}"
clone hg bitbucket.org/ww/goautoneg 75cd24fc2f2c2a2088577d12123ddee5f54e0675
clone git github.com/Sirupsen/logrus 51fe59aca108dc5680109e7b2051cbdcfa5a253c
clone git github.com/beorn7/perks/quantile b965b613227fddccbfffe13eae360ed3fa822f8d
clone git github.com/codegangsta/cli f445c894402839580d30de47551cedc152dad814
clone git github.com/davecgh/go-spew/spew 3e6e67c4dcea3ac2f25fd4731abc0e1deaf36216
clone git github.com/docker/docker/pkg/mount 2b27fe17a1b3fb8472fde96d768fa70996adf201
clone git github.com/docker/docker/pkg/units 2b27fe17a1b3fb8472fde96d768fa70996adf201
clone git github.com/ghodss/yaml 73d445a93680fa1a78ae23a5839bad48f32ba1ee
clone git github.com/golang/glog 44145f04b68cf362d9c4df2182967c2275eaefed
clone git github.com/golang/protobuf/proto 7f07925444bb51fa4cf9dfe6f7661876f8852275
clone git github.com/google/gofuzz bbcb9da2d746f8bdbd6a936686a0a6067ada0ec5
clone git github.com/gorilla/context 215affda49addc4c8ef7e2534915df2c8c35c6cd
clone git github.com/gorilla/mux 8096f47503459bcc74d1f4c487b7e6e42e5746b5
clone git github.com/juju/ratelimit 77ed1c8a01217656d2080ad51981f6e99adaa177
clone git github.com/matttproud/golang_protobuf_extensions/pbutil fc2b8d3a73c4867e51861bbdd5ae3c1f0869dd6a
clone git github.com/opencontainers/runc/libcontainer/cgroups 11f8fdca33b27d77c78d0c44009ae00f0215b050
clone git github.com/opencontainers/runc/libcontainer/configs 11f8fdca33b27d77c78d0c44009ae00f0215b050
clone git github.com/opencontainers/runc/libcontainer/system 11f8fdca33b27d77c78d0c44009ae00f0215b050
clone git github.com/pborman/uuid ca53cad383cad2479bbba7f7a1a05797ec1386e4
clone git github.com/prometheus/client_golang/prometheus 3b78d7a77f51ccbc364d4bc170920153022cfd08
clone git github.com/prometheus/client_model/go fa8ad6fec33561be4280a8f0514318c79d7f6cb6
clone git github.com/prometheus/common/expfmt ef7a9a5fb138aa5d3a19988537606226869a0390
clone git github.com/prometheus/common/model ef7a9a5fb138aa5d3a19988537606226869a0390
clone git github.com/prometheus/procfs 490cc6eb5fa45bf8a8b7b73c8bc82a8160e8531d
clone git github.com/spf13/pflag 08b1a584251b5b62f458943640fc8ebd4d50aaa5
clone git github.com/ugorji/go/codec f1f1a805ed361a0e078bb537e4ea78cd37dcf065
clone git github.com/vishvananda/netlink c24b290c8fe549cd5be941445f918e83c8efa966
clone git golang.org/x/crypto/ssh c84e1f8e3a7e322d497cd16c0e8a13c7e127baf3
clone git golang.org/x/net/context c2528b2dd8352441850638a8bb678c2ad056fd3e
clone git gopkg.in/yaml.v2 d466437aa4adc35830964cffc5b5f262c63ddcb4
clone git k8s.io/kubernetes/pkg/api 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/pkg/auth/user 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/pkg/conversion 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/pkg/fields 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/pkg/labels 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/pkg/registry/service/allocator 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/pkg/registry/service/ipallocator 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/pkg/runtime 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/pkg/types 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/pkg/util 92643403382613e0530e442544573e0aa25b6187
clone git k8s.io/kubernetes/third_party/forked/reflect 92643403382613e0530e442544573e0aa25b6187
clone git speter.net/go/exp/math/dec/inf 42ca6cd68aa922bc3f32f1e056e61b65945d9ad7
