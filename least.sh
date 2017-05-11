#!/bin/bash

for (( c = 1; ; c++ )) do
  if [ ! -f "$c.meta" ]; then
    break
  fi
  less "$c.meta"
  less "$c.initiator"
  less "$c.responder"
done




