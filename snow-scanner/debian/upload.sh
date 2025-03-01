#!/bin/sh

user=$(git config github.user)
token=$(git config github.token)


if [ -z "$token" ]; then
    echo 'Token is empty. Please run git config --add github.token "ChangeMe"';
    exit 1;
fi

if [ -z "$user" ]; then
    echo 'User is empty. Please run git config --add github.user "ChangeMe"';
    exit 1;
fi

if [ -z "$1" ]; then
    echo 'Package file is missing, please provide a .deb file';
    exit 1;
fi

curl --user $user:$token \
     --upload-file "$1" \
     -v \
     -# \
     https://git.wdes.eu/api/packages/wdes/debian/pool/bookworm/main/upload
