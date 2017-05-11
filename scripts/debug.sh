#!/bin/bash

for (( c = 1; ; c++ )) do
  if [ ! -f "debug/$c.client" ]; then
    break
  fi
  less "debug/$c.client"
  less "debug/$c.server"
done
