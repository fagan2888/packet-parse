#!/bin/bash

for (( c = 1; ; c++ )) do
  if [ ! -f "output/$c.meta" ]; then
    break
  fi
  less "output/$c.meta"
  less "output/$c.initiator"
  less "output/$c.responder"
done
