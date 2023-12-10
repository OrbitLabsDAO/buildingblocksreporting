#!/bin/bash

# Detect param or set default to local:
if [ -z $1 ]
then
echo -e 'No environment param set.\n Defaulting to local'
export ELEVENTY_ENV='local'
else 
export ELEVENTY_ENV=$1
fi



wipeOutOldBuild () {
    echo 'Wiping out old build directory'
    rm -rf ./_site/**
}

#delete the files in the site dir
wipeOutOldBuild
#run eleventy
#pkill -9 esbuild

npx @11ty/eleventy 

echo "killing rouge wrangler"

PORT=8789

# Find and kill the Node.js process using port 8789
NODE_PID=$(lsof -i :$PORT -sTCP:LISTEN -t)
if [ -z "$NODE_PID" ]; then
  echo "No Node.js process found on port $PORT"
else
  # Forcefully terminate the Node.js process
  echo "Killing Node.js process with PID $NODE_PID"
  kill -9 "$NODE_PID"
fi

echo "starting wrangler"


#åwrangler pages dev _site --port 8789 --d1=DB --persist --binding SECRET=fdfdf  --kv=kvdata --local --live-reload  &

npx wrangler pages dev _site --port 8789  --binding SECRET=fdfdf  --kv=kvdata --local --live-reload  &


if [[ $ELEVENTY_ENV == 'cypress' ]]
then
echo "wiping KV stores"
rm -rf ./.mf/**
echo "Running cypress tests"
npx cypress run --record --key 6f7af59a-6998-42b3-8a70-48f2e890566b
exit
fi

