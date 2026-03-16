#!/bin/bash

# Workspace directories
PDP_DIR="/tmp/PDP_workspace"
PEP_DIR="/tmp/PEP_workspace"
CA_DIR="/tmp/CA_workspace"

USER_NAME="zerotrust"

echo "Fixing ownership..."

sudo chown $USER_NAME:$USER_NAME -R $PDP_DIR
sudo chown $USER_NAME:$USER_NAME -R $PEP_DIR
sudo chown $USER_NAME:$USER_NAME -R $CA_DIR

echo "Setting permissions..."

sudo chmod 700 -R $CA_DIR
sudo chmod 700 -R $PEP_DIR
sudo chmod 700 -R $PDP_DIR

echo "Workspace permissions fixed successfully."
