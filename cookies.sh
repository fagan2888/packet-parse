#!/bin/bash

for (( c = 1; ; c++ )) do
  if [ ! -f "$c.cookie" ]; then
    break
  fi
  less "$c.cookie"
done
