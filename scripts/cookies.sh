#!/bin/bash

for (( c = 1; ; c++ )) do
  if [ ! -f "output/$c.cookie" ]; then
    break
  fi
  less "output/$c.cookie"
done
