#! /usr/bin/env bash
###################
###     SSH     ###
###################

DROPLET_TAG='RicardoHome'
DROPLET_NAME="${DROPLET_TAG/_/-}"
echo -e 'n\n' | ssh-keygen -t rsa -f ~/.ssh/${DROPLET_NAME} -P "" -C "${DROPLET_NAME}"
SSH_KEYPATH="$HOME/.ssh/$DROPLET_NAME"
SSH_FINGERPRINT=$(ssh-keygen -l -E md5 -f "$SSH_KEYPATH.pub" | awk '{ print $2 }' | sed 's|MD5:||')


###################
###   DROPLET   ###
###################
NAME=${2:-"wg-$(date +%s)"}
REGION=${3:-"nyc1"}
IMAGE=${4:-"ubuntu-20-04-x64"}
SIZE=${5:-"s-1vcpu-1gb"}

if [[ -z $DIGITAL_OCEAN_TOKEN ]]; then
    echo "Digital Ocean access token must be set"
    exit 1
fi

#                             __...------------._
#                          ,-'                   `-.
#                       ,-'                         `.
#                     ,'                            ,-`.
#                    ;                              `-' `.
#                   ;                                 .-. \
#                  ;                           .-.    `-'  \
#                 ;                            `-'          \
#                ;                                          `.
#                ;                                           :
#               ;                                            |
#              ;                                             ;
#             ;                            ___              ;
#            ;                        ,-;-','.`.__          |
#        _..;                      ,-' ;`,'.`,'.--`.        |
#       ///;           ,-'   `. ,-'   ;` ;`,','_.--=:      /
#      |'':          ,'        :     ;` ;,;,,-'_.-._`.   ,'
#      '  :         ;_.-.      `.    :' ;;;'.ee.    \|  /
#       \.'    _..-'/8o. `.     :    :! ' ':8888)   || /
#        ||`-''    \\88o\ :     :    :! :  :`""'    ;;/
#        ||         \"88o\;     `.    \ `. `.      ;,'
#        /)   ___    `."'/(--.._ `.    `.`.  `-..-' ;--.
#        \(.="""""==.. `'-'     `.|      `-`-..__.-' `. `.
#         |          `"==.__      )                    )  ;
#         |   ||           `"=== '                   .'  .'
#         /\,,||||  | |           \                .'   .'
#         | |||'|' |'|'           \|             .'   _.' \
#         | |\' |  |           || ||           .'    .'    \
#         ' | \ ' |'  .   ``-- `| ||         .'    .'       \
#           '  |  ' |  .    ``-.._ |  ;    .'    .'          `.
#        _.--,;`.       .  --  ...._,'   .'    .'              `.__
#      ,'  ,';   `.     .   --..__..--'.'    .'                __/_\
#    ,'   ; ;     |    .   --..__.._.'     .'                ,'     `.
#   /    ; :     ;     .    -.. _.'     _.'                 /         `
#  /     :  `-._ |    .    _.--'     _.'                   |
# /       `.    `--....--''       _.'                      |
#           `._              _..-'                         |
#              `-..____...-''                              |
#                                                          |
#                                mGk                       |
# https://www.asciiart.eu/movies/star-wars
trap 'cleanup' ERR SIGINT SIGTERM SIGKILL

#######################################
# Cleans up wireguard interface and deletes droplet
#######################################
function cleanup {
    if [[ -n $(ip addr | grep wg0) ]]; then
        echo "Shutting down wg0 connection"
        sudo wg-quick down wg0
    fi
    echo "Removing droplet..."
    doctl compute droplet delete $NAME -f
    exit 1
}

#######################################
# Timeout until counter is reached, or command executes
# Arguments:
#   Command to execute
# Outputs:
#   0 or 1 if counter is maxed out
#######################################
function wait_til {
    local counter=0
    until [[ $counter -eq 20 ]] || $1; do
        echo "Waiting for $((++counter))"
        sleep $counter
    done
    [[ $counter -lt 20 ]]
}

#######################################
# Execute a command on the droplet
# Arguments:
#   Command
# Outputs:
#   stdout
#######################################
function exec_droplet {
    doctl compute ssh $NAME \
        --ssh-key-path $SSH_KEYPATH \
        --ssh-command "$@"
}

#######################################
# Check to see if we have a droplet already
#######################################
function check_for_active_droplet {
    echo "Checking for previous Wireguard droplet..."
    local droplet=$(doctl compute droplet list --tag-name "wireguard" | tail -n +2)
    if [[ -n $droplet ]]; then
        echo "Found droplet. Bringing up interface."
        start_wireguard_connection
        exit 0
    fi
    echo "No droplet found. Proceeding with creation."
}

#######################################
# Creates a new wireguard droplet
#######################################
function create_droplet {
    doctl compute ssh-key create ${DROPLET_NAME} --public-key "$(cat ~/.ssh/${DROPLET_NAME}.pub)"
    echo "Creating droplet..."
    doctl compute droplet create \
        $NAME \
        --size $SIZE \
        --image $IMAGE \
        --region $REGION \
        --tag-name "wireguard" \
        --user-data "$(envsubst '${DIGITAL_OCEAN_TOKEN}' < cloud-init-user-script.sh)" \
        --ssh-keys $SSH_FINGERPRINT \
        --enable-ipv6 \
        --wait 
    echo "Droplet is now active!"

    IPv4=$(doctl compute droplet list $NAME --format 'Public IPv4' | tail -n 1)
    echo "IP is $IPv4"
}

#######################################
# Waits until port 22/TCP is open
# Outputs:
#   stderr if can not connect
#######################################
function wait_for_ssh {
    echo "Waiting for SSH to become available"
    wait_til "nc -vz $IPv4 22"
    if [[ $? == 1 ]]; then
        echo 'Could not connect with SSH' >&2
    fi
}

#######################################
# Authorize SSH connections to droplet 
#######################################
function authorize_ssh_connection {
    echo "Authorizing SSH connection to droplet"
    ssh-keyscan -H $IPv4 >> $HOME/.ssh/known_hosts
}

#######################################
# Waits until port 51820/UDP is open
# Outputs:
#   stderr if can not connect
#######################################
function wait_for_wireguard {
    echo "Waiting for Wireguard to become available"
    wait_til "nc -uvz $IPv4 51820"
    if [[ $? == 1 ]]; then
        echo 'Could not connect with WireGuard' >&2
    fi
}

#######################################
# Creates a local wireguard client
#######################################
function create_wireguard_client {
    umask 077
    sleep 60
    local SERVER_PUBLIC_KEY=$(exec_droplet "cat /server.pub")
    local GATEWAY_KEY=$(exec_droplet "cat /gateway.key")
    local GATEWAY_FILE="gateway.conf"

    local MACBOOK_KEY=$(exec_droplet "cat /macbook.key")
    local MACBOOK_FILE="macbook.conf"

cat << EOF > $GATEWAY_FILE
[Interface]
Address = 10.200.0.2/32
Address = fd86:ea04:1111::2/128
PostUp = iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.200.0.0/24 -j MASQUERADE
PrivateKey = $GATEWAY_KEY
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $IPv4:51820
AllowedIPs = 10.200.0.0/24,10.0.0.0/24,192.168.100.0/24,192.168.0.0/24
EOF

cat << EOF > $MACBOOK_FILE
[Interface]
Address = 10.200.0.3/32
Address = fd86:ea04:1111::3/128
PrivateKey = $MACBOOK_KEY
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $IPv4:51820
AllowedIPs = 10.200.0.0/24,10.0.0.0/24,192.168.100.0/24,192.168.0.0/24
EOF

}

#######################################
# Allows client to connect to server
#######################################
function add_client_to_server {
    local CLIENT_PUBLIC_KEY=$(cat publickey)
    exec_droplet "wg set wg0 peer $CLIENT_PUBLIC_KEY allowed-ips 10.0.0.2/32,fd86:ea04:1111::2/128"
    exec_droplet "wg-quick save wg0"
}

#######################################
# Starts connection to droplet via wireguard
#######################################
function start_wireguard_connection {
    sudo wg-quick up wg0
}

#######################################
# Initialization function
#######################################
function init {
    check_for_active_droplet
    create_droplet
    wait_for_ssh
    authorize_ssh_connection
    wait_for_wireguard
    create_wireguard_client
    # add_client_to_server
    # start_wireguard_connection
    exit 0
}

init