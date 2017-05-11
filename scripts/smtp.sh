#!/bin/bash

for (( c = 1; ; c++ )) do
  if [ ! -f "output/$c.mail" ]; then
    break
  fi
  less "output/$c.mail"
done
