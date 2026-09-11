#!/bin/sh
set -eu

mkdir -p /app/data/state/config
cp /seed/config.json /app/data/state/config/config.json

cd /mnt/files
for dir in shared team-1 team-2 projects finance hidden; do
    mkdir -p "$dir"
    echo "$dir" > "$dir/readme.txt"
done
echo "not a folder" > notes.txt
ln -sfn ../team-2 team-1/escape
ln -sfn /etc team-1/etc

chown -R filestash:filestash /app/data/state /mnt/files
