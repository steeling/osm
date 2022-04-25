#! /bin/bash

Usage()
{
   # Display Help
   echo "Usage: debugger [options] <target>."
   echo
   echo "target is the service or IP address of the target to run network diagnostics against."
   echo
   echo "options:"
   echo "-s     scheme: HTTP or HTTPS are supported."
   echo "-h     Print this Help."
}

# help, target, certs, 
while getopts ":hn:" option; do
    case $option in
        h) # display Help
            echo "h option.."
            Usage
            exit 0
            ;;
        s) # Enter a name
            SCHEME=$OPTARG
            ;;
        \?) # Invalid option
            echo "Error: Invalid option"
            exit;;
   esac
done

shift $((OPTIND-1))

echo $#

if [ $# -ne 1 ]; then
   Usage
   exit 1
fi

set -x

TARGET=$@

ifconfig
dig $TARGET
nslookup $TARGET
curl -v $TARGET
ping -c 1 $TARGET