#!/bin/bash

# Number of servers
LXC_COUNT=4

# Port the server is running apache2 on
LXC_PORT=8080

# Load balancer client facing ip6 address
LB_IP=2001:db8:aaaa::2

# Load balancer client facing port
LB_PORT=80

# State to reverse map server lxc to corresponding load balancer for dsr
LB_STATE=200

# Array of server lxc ip
LXC_IP_ARR=()

# Array of server lxc
SERVER_LXC_ARR=()


function fini()
{
	vagrant halt
	vagrant destroy
}

#trap fini EXIT

function init()
{
	local NODE_NAME=$1

	vagrant up $NODE_NAME --provider=libvirt

	node_run_quiet $NODE_NAME "docker pull challa/ubuntu"
}

function node_run() {
        NODE=$1
        shift

        echo "Running on ${NODE}: $*"
        vagrant ssh $NODE -- -t "$*"
}

function node_run_quiet() {
        NODE=$1
        shift

        vagrant ssh $NODE -- -t "$*"
}

function setup_recorder() {
	NODE=$1

	node_run_quiet $NODE "sudo apt-get -y install software-properties-common"
	node_run_quiet $NODE "sudo apt-add-repository -y ppa:zanchey/asciinema"
	node_run_quiet $NODE "sudo apt-get update"
	node_run_quiet $NODE "sudo apt-get -y install pip"
	node_run_quiet $NODE "sudo pip install pkg_resources"
	node_run_quiet $NODE "sudo apt-get -y install asciinema"
	node_run_quiet $NODE "sudo apt-get -y install tshark"
}

function start_containers() {
	CLIENT_LXC1=$(node_run_quiet client "docker run -d --net cilium -l io.cilium.client --name client1 challa/ubuntu tail -f /dev/null")
	CLIENT_LXC2=$(node_run_quiet client "docker run -d --net cilium -l io.cilium.client --name client2 challa/ubuntu tail -f /dev/null")

	LB_CMD="$LB_IP $LB_PORT $LB_STATE $LXC_COUNT"

	for ((i=0;i<$LXC_COUNT;i++)); do
		SERVER_LXC_ARR[$i]=$(node_run_quiet server "docker run -d --net cilium -l io.cilium.server --name server_$i challa/ubuntu tail -f /dev/null")
		LXC_IP_ARR[$i]=$(node_run_quiet server "docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server_$i" | tr -d '\r')
		echo "server_$i IPv6: ${LXC_IP_ARR[$i]}"
		NODE_ID="0x$(echo ${LXC_IP_ARR[$i]} | sed s/::/:/ | cut -d : -f 2,3 | sed s/://g)"
		LXC_ID="$(echo ${LXC_IP_ARR[$i]} | cut -d : -f 6)"
		LXC_IDX=0x$LXC_ID
		LB_CMD="$LB_CMD $LXC_IDX $LXC_PORT $NODE_ID"
		node_run_quiet server "docker exec -i server_$i service apache2 start"
		node_run_quiet server "cilium endpoint config $((16#$LXC_ID)) Policy=disabled"
	done

	echo "LB_CMD : $LB_CMD"

	node_run_quiet lb "echo sudo cilium lb u /sys/fs/bpf/tc/globals/cilium_lb_services 1 $LB_CMD > /home/vagrant/lbcmd.sh"
	node_run_quiet lb "chmod 755 /home/vagrant/lbcmd.sh"
	#node_run_quiet lb "/home/vagrant/lbcmd.sh"

	node_run_quiet server "echo sudo cilium lb u /sys/fs/bpf/tc/globals/cilium_lb_state 2 $LB_CMD > /home/vagrant/lbcmd.sh"
	node_run_quiet server "chmod 755 /home/vagrant/lbcmd.sh"
	#node_run_quiet server "/home/vagrant/lbcmd.sh"
}

function run_server() {
	echo "cilium server endpoints"

	node_run_quiet server "cilium endpoint list"

	node_run_quiet server "docker ps -a"

	echo "configuring load balancer on lb node"

	node_run_quiet lb "/home/vagrant/lbcmd.sh"

	echo "configuring direct server return on server node"

	node_run_quiet server "/home/vagrant/lbcmd.sh"

	echo "Starting packet capture on eth1 ..."

	node_run_quiet lb "sudo tcpdump -nn -i eth1 -w /home/vagrant/lb.pcap -c 10 ip6 and tcp"

	node_run_quiet lb "sudo tshark -r /home/vagrant/lb.pcap"
}

function run_client() {
	node_run_quiet client "docker exec -i client1 /bin/curl.sh 5 2" & 
	sleep 5
	node_run_quiet client "docker exec -i client2 /bin/curl.sh 5 2" && fg
}

function stop_containers() {
	node_run client "docker rm -f client1 2> /dev/null" || true
	node_run client "docker rm -f client2 2> /dev/null" || true
	for ((i=0;i<$LXC_COUNT;i++)); do
		node_run server "docker rm -f server_$i 2> /dev/null" || true
	done
}
