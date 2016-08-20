#!/bin/bash
set -x

source lb.sh

echo "Bringing up server node"
init server

echo "Bringing up load balancer node"
init lb

echo "Bringing up client node"
init client

echo "Setting up recorder on server"
setup_recorder server

echo "Setting up recorder on load balancer"
setup_recorder lb

echo "Setting up recorder on client"
setup_recorder client

echo "Bringing up server containers"
start_containers
