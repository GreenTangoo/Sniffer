#!/bin/bash

make clean

if [[ ! -d "build" ]]; then
	mkdir build;
fi

if [[ ! -f "build/incoming_logs.txt" ]]; then
	touch build/incoming_logs.txt;
fi

if [[ ! -f "build/outcoming_logs.txt" ]]; then
	touch build/outcoming_logs.txt;
fi

make all
