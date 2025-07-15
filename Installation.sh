#!/bin/bash
sudo apt update
sudo apt install python3-pip -y
sudo apt install -y libffi-dev python3-dev build-essential
pip install -r requirements.txt
