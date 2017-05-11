#!/bin/bash

for (( c = 1; ; c++ )) do
  if [ ! -f "$c.mail" ]; then
    break
  fi
  less "$c.mail"
done
