#!/bin/bash

error_exit() {
    echo "Error: $1" >&2
    exit 1
}

run_command() {
    echo "Running: $1"
    eval "$1" || error_exit "failed: $1"
}

if ! command -v sshpass &> /dev/null; then
    echo "sshpass is not found installing it"
    run_command "sudo apt update && sudo apt install sshpass -y"
else
    echo "sshpass is already installed."
fi

echo "==============================================================="
echo "PARTIE 1: COLLECTING NODES INFO"
echo "==============================================================="

read -p "Enter number of nodes you want: " NODE_COUNT
declare -A NODES
declare -a NODE_IPS

echo "Need info for all nodes:"
for ((i=1; i<=NODE_COUNT; i++)); do
    read -p "IP for Node $i: " NODE_IP
    read -s -p "SSH password for Node $i: " SSH_PASSWORD
    echo
    NODES["$NODE_IP"]="$SSH_PASSWORD"
    NODE_IPS[$i-1]="$NODE_IP"
done

read -p "Cluster name: " CLUSTER_NAME
read -p "Kibana IP: " KIBANA_IP
read -s -p "Kibana SSH password: " KIBANA_SSH_PASSWORD
echo

echo "==============================================================="
echo "PARTIE 2: EXPANDING DISK SPACE ON UBUNTU SERVERS"
echo "==============================================================="

for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    echo "===== EXPANDING DISK FOR NODE: $IP ====="
    
    echo "Checking the current space first on $IP..."
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'df -h'"
    
    echo "Detecting LVM setup..."
    LVM_CHECK1=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'sudo lvs 2>/dev/null || echo "NO_LVM1"')
    LVM_CHECK2=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'sudo vgs 2>/dev/null || echo "NO_LVM2"')
    LVM_PATH_CHECK=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'ls -la /dev/mapper/ 2>/dev/null || echo "NO_MAPPER"')
    
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv 2>/dev/null || echo \"Methode 1 failed - trying alternatives\"'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv 2>/dev/null || echo \"Method 1 resize failed\"'"
    
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv 2>/dev/null || echo \"Methode 2 failed - trying alternatives\"'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv 2>/dev/null || echo \"Methode 2 resize failed\"'"
    
    LVS_OUTPUT=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'sudo lvs --noheadings -o lv_path 2>/dev/null | head -1 || echo "NO_LVS"')
    if [[ "$LVS_OUTPUT" != "NO_LVS" && "$LVS_OUTPUT" != "" ]]; then
        LV_PATH=$(echo "$LVS_OUTPUT" | tr -d '[:space:]')
        echo "Found LV path: $LV_PATH, extending it..."
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo lvextend -l +100%FREE $LV_PATH 2>/dev/null || echo \"Method 3 failed\"'"
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo resize2fs $LV_PATH 2>/dev/null || echo \"Method 3 resize failed\"'"
    fi
    
    ROOT_FS=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'mount | grep " / " | cut -d " " -f 1 || echo "NO_ROOT"')
    if [[ "$ROOT_FS" != "NO_ROOT" && "$ROOT_FS" != "" ]]; then
        echo "Found root fs: $ROOT_FS, trying resize..."
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo resize2fs $ROOT_FS 2>/dev/null || echo \"Method 4 resize failed\"'"
    fi
    
    echo "Space after expansion:"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'df -h'"
    echo "===== FINISHED WITH NODE: $IP ====="
done

if [[ ! " ${NODE_IPS[@]} " =~ " $KIBANA_IP " ]]; then
    echo "===== EXPANDING DISK SPACE FOR KIBANA - IMPORTANT ====="
    echo "Checking space on $KIBANA_IP..."
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'df -h'"
    
    echo "Checking LVM on Kibana..."
    LVM_CHECK1=$(sshpass -p "$KIBANA_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$KIBANA_IP" 'sudo lvs 2>/dev/null || echo "NO_LVM1"')
    LVM_CHECK2=$(sshpass -p "$KIBANA_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$KIBANA_IP" 'sudo vgs 2>/dev/null || echo "NO_LVM2"')
    LVM_PATH_CHECK=$(sshpass -p "$KIBANA_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$KIBANA_IP" 'ls -la /dev/mapper/ 2>/dev/null || echo "NO_MAPPER"')
    
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv 2>/dev/null || echo \"Method 1 failed - trying alternatives\"'"
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv 2>/dev/null || echo \"Method 1 resize failed\"'"
    
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv 2>/dev/null || echo \"Method 2 failed - trying alternatives\"'"
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv 2>/dev/null || echo \"Method 2 resize failed\"'"
    
    LVS_OUTPUT=$(sshpass -p "$KIBANA_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$KIBANA_IP" 'sudo lvs --noheadings -o lv_path 2>/dev/null | head -1 || echo "NO_LVS"')
    if [[ "$LVS_OUTPUT" != "NO_LVS" && "$LVS_OUTPUT" != "" ]]; then
        LV_PATH=$(echo "$LVS_OUTPUT" | tr -d '[:space:]')
        echo "Found LV path: $LV_PATH, extending..."
        run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo lvextend -l +100%FREE $LV_PATH 2>/dev/null || echo \"Method 3 failed\"'"
        run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo resize2fs $LV_PATH 2>/dev/null || echo \"Method 3 resize failed\"'"
    fi
    
    ROOT_FS=$(sshpass -p "$KIBANA_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$KIBANA_IP" 'mount | grep " / " | cut -d " " -f 1 || echo "NO_ROOT"')
    if [[ "$ROOT_FS" != "NO_ROOT" && "$ROOT_FS" != "" ]]; then
        echo "Found root fs: $ROOT_FS, trying resize..."
        run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo resize2fs $ROOT_FS 2>/dev/null || echo \"Method 4 resize failed\"'"
    fi
    
    echo "Space after expansion:"
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'df -h'"
    echo "===== FINISHED WITH KIBANA ====="
fi

echo "==============================================================="
echo "PARTIE 3: CONFIGURING HOSTS ON NODES "
echo "==============================================================="

echo "setting up /etc/hosts on all nodes for better discovery"
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    HOSTNAME=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'hostname')
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'grep -q \"$IP $HOSTNAME\" /etc/hosts || echo \"$IP $HOSTNAME\" | sudo tee -a /etc/hosts'"
done

if [[ ! " ${NODE_IPS[@]} " =~ " $KIBANA_IP " ]]; then
    KIBANA_HOSTNAME=$(sshpass -p "$KIBANA_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$KIBANA_IP" 'hostname')
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'grep -q \"$KIBANA_IP $KIBANA_HOSTNAME\" /etc/hosts || echo \"$KIBANA_IP $KIBANA_HOSTNAME\" | sudo tee -a /etc/hosts'"
fi

for SRC_IP in "${NODE_IPS[@]}"; do
    SRC_PASSWORD=${NODES["$SRC_IP"]}
    for DST_IP in "${NODE_IPS[@]}"; do
        if [ "$SRC_IP" != "$DST_IP" ]; then
            DST_HOSTNAME=$(sshpass -p "${NODES["$DST_IP"]}" ssh -o StrictHostKeyChecking=no "$DST_IP" 'hostname')
            run_command "sshpass -p '$SRC_PASSWORD' ssh -o StrictHostKeyChecking=no $SRC_IP 'grep -q \"$DST_IP $DST_HOSTNAME\" /etc/hosts || echo \"$DST_IP $DST_HOSTNAME\" | sudo tee -a /etc/hosts'"
        fi
    done
    
    if [[ ! " ${NODE_IPS[@]} " =~ " $KIBANA_IP " ]]; then
        run_command "sshpass -p '$SRC_PASSWORD' ssh -o StrictHostKeyChecking=no $SRC_IP 'grep -q \"$KIBANA_IP $KIBANA_HOSTNAME\" /etc/hosts || echo \"$KIBANA_IP $KIBANA_HOSTNAME\" | sudo tee -a /etc/hosts'"
    fi
done

declare -A NODE_HOSTNAMES
for NODE_IP in "${NODE_IPS[@]}"; do
    NODE_PASSWORD=${NODES["$NODE_IP"]}
    NODE_HOSTNAME=$(sshpass -p "$NODE_PASSWORD" ssh -o StrictHostKeyChecking=no "$NODE_IP" 'hostname')
    NODE_HOSTNAMES["$NODE_IP"]="$NODE_HOSTNAME"
done

echo "==============================================================="
echo "PARTIE 4: INSTALLING ELASTICSEARCH"
echo "==============================================================="

NODE_DIRS=()
for ((i=0; i<NODE_COUNT; i++)); do
    IP="${NODE_IPS[$i]}"
    PASSWORD=${NODES["$IP"]}
    HOSTNAME=${NODE_HOSTNAMES["$IP"]}
    echo "Setting up ES on $HOSTNAME ($IP)..."

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'if ! command -v java &> /dev/null; then sudo apt update && sudo apt install openjdk-17-jdk -y; else echo \"Java's already installed.\"; fi'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'id -u elasticsearch &>/dev/null || sudo useradd elasticsearch -m -s /bin/bash'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'if [ ! -f /etc/security/limits.d/elasticsearch.conf ]; then sudo tee /etc/security/limits.d/elasticsearch.conf > /dev/null << EOF
elasticsearch soft nofile 65535
elasticsearch hard nofile 65535
elasticsearch soft nproc 4096
elasticsearch hard nproc 4096
EOF
else
    echo \"system limits already set-up.\"
fi'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo sysctl -w vm.max_map_count=262144'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'grep -q \"vm.max_map_count=262144\" /etc/sysctl.conf || sudo bash -c \"echo vm.max_map_count=262144 >> /etc/sysctl.conf\"'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP '
if [ ! -f elasticsearch-8.17.3-linux-x86_64.tar.gz ]; then
    echo \"Downloading ES...\"
    wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.3-linux-x86_64.tar.gz
    wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.3-linux-x86_64.tar.gz.sha512
    shasum -a 512 -c elasticsearch-8.17.3-linux-x86_64.tar.gz.sha512
else
    echo \"ES is alreadyy downloaded.\"
fi'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP '
if [ ! -d elasticsearch-8.17.3 ]; then
    echo \"Extracting ES...\"
    tar -xzf elasticsearch-8.17.3-linux-x86_64.tar.gz
else
    echo \"ES is already extracted.\"
fi'"
    
    NODE_DIRS+=("/home/elasticsearch")
    
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /home/elasticsearch'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo cp -rf elasticsearch-8.17.3/* /home/elasticsearch/'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /var/lib/elasticsearch /var/log/elasticsearch'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /var/lib/elasticsearch /var/log/elasticsearch'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /home/elasticsearch/config/jvm.options.d'"
    
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /home/elasticsearch/config/certs'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch/config/certs'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo tee /home/elasticsearch/config/jvm.options.d/heap.options > /dev/null << EOF
-Xms1g
-Xmx1g
EOF'"

    read -p "Roles for $HOSTNAME (comma-sep, e.g., master,data,ingest): " NODE_ROLES_INPUT
    
    NODE_ROLES=()
    IFS=',' read -ra NODE_ROLES <<< "$NODE_ROLES_INPUT"
    NODE_ROLES_FORMATTED=" ${NODE_ROLES[0]}"
    for ((j=1; j<${#NODE_ROLES[@]}; j++)); do
        NODE_ROLES_FORMATTED="$NODE_ROLES_FORMATTED, ${NODE_ROLES[$j]}"
    done
    NODE_ROLES_FORMATTED="$NODE_ROLES_FORMATTED "
    
    IP_ARRAY=( "${NODE_IPS[@]}" )
    SEED_HOSTS=$(printf ",\"%s\"" "${IP_ARRAY[@]}")
    SEED_HOSTS=${SEED_HOSTS:1}
    
    HOSTNAME_ARRAY=()
    for NODE_IP in "${NODE_IPS[@]}"; do
        HOSTNAME_ARRAY+=("${NODE_HOSTNAMES[$NODE_IP]}")
    done
    MASTER_NODES=$(printf ",\"%s\"" "${HOSTNAME_ARRAY[@]}")
    MASTER_NODES=${MASTER_NODES:1}

    CONFIG="cluster.name: $CLUSTER_NAME
node.name: $HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]

xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: changeme
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: changeme

xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.http.ssl.keystore.password: changeme
xpack.security.http.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.http.ssl.truststore.password: changeme"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo bash -c \"echo \\\"$CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo tee /etc/systemd/system/elasticsearch.service > /dev/null << EOF
[Unit]
Description=Elasticsearch
Documentation=https://www.elastic.co
Wants=network-online.target
After=network-online.target

[Service]
User=elasticsearch
Group=elasticsearch
ExecStart=/home/elasticsearch/bin/elasticsearch
Environment=ES_HOME=/home/elasticsearch
Environment=ES_PATH_CONF=/home/elasticsearch/config
Environment=PID_DIR=/var/run/elasticsearch
LimitNOFILE=65535
LimitNPROC=4096
LimitMEMLOCK=infinity
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl daemon-reload'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl enable elasticsearch'"
done

echo "==============================================================="
echo "PARTIE 5: GENERATING & DISTRIBUTING THE CERTIFS"
echo "==============================================================="

echo "=== Certificate Generation ==="
echo "Which node will generate certs?"
read -p "Cert generation node IP: " CERT_NODE_IP

if [[ ! "${NODES[$CERT_NODE_IP]}" ]]; then
    error_exit "IP $CERT_NODE_IP not in nodes list. Restart script."
fi

CERT_NODE_PASSWORD=${NODES["$CERT_NODE_IP"]}
echo "Generating certs on $CERT_NODE_IP..."

CERT_PASSWORD="lolchangeme"

echo "Checking for existing certs..."
CERTS_EXIST=$(sshpass -p "$CERT_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no "$CERT_NODE_IP" 'if [ -f /home/elasticsearch/config/certs/elastic-stack-ca.p12 ] && [ -f /home/elasticsearch/config/certs/elastic-certificates.p12 ]; then echo "yes"; else echo "no"; fi')

if [ "$CERTS_EXIST" == "yes" ]; then
    echo "Certs already exist. Use existing or generate new?"
    select cert_option in "Use existing" "Generate new"; do
        case $cert_option in
            "Use existing")
                echo "Using existing certs..."
                break
                ;;
            "Generate new")
                echo "Will generate new certs..."
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo rm -f /home/elasticsearch/config/certs/elastic-stack-ca.p12 /home/elasticsearch/config/certs/elastic-certificates.p12'"
                
                echo "Looking for elasticsearch-certutil..."
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'ls -la /home/elasticsearch/bin/elasticsearch-certutil || echo \"Tool not found in expected location\"'"

                echo "Creating CA cert with pass '$CERT_PASSWORD'..."
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-certutil ca --out /home/elasticsearch/config/certs/elastic-stack-ca.p12 --pass $CERT_PASSWORD'"

                echo "Creating node certs with pass '$CERT_PASSWORD'..."
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-certutil cert --ca /home/elasticsearch/config/certs/elastic-stack-ca.p12 --out /home/elasticsearch/config/certs/elastic-certificates.p12 --pass $CERT_PASSWORD --ca-pass $CERT_PASSWORD'"
                
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chmod 640 /home/elasticsearch/config/certs/*.p12'"
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/config/certs/*.p12'"
                break
                ;;
        esac
    done
else
    echo "Checking for elasticsearch-certutil..."
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'ls -la /home/elasticsearch/bin/elasticsearch-certutil || echo \"Tool not found in expected location\"'"

    echo "Creating CA cert with pass '$CERT_PASSWORD'..."
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-certutil ca --out /home/elasticsearch/config/certs/elastic-stack-ca.p12 --pass $CERT_PASSWORD'"

    echo "Creating node certs with pass '$CERT_PASSWORD'..."
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-certutil cert --ca /home/elasticsearch/config/certs/elastic-stack-ca.p12 --out /home/elasticsearch/config/certs/elastic-certificates.p12 --pass $CERT_PASSWORD --ca-pass $CERT_PASSWORD'"
    
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chmod 640 /home/elasticsearch/config/certs/*.p12'"
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/config/certs/*.p12'"
fi

echo "copying certs to all nodes now..."
for IP in "${NODE_IPS[@]}"; do
    if [ "$IP" != "$CERT_NODE_IP" ]; then
        PASSWORD=${NODES["$IP"]}
        echo "Copying certs to node $IP..."
        
        run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo cp /home/elasticsearch/config/certs/elastic-stack-ca.p12 /tmp/'"
        run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo cp /home/elasticsearch/config/certs/elastic-certificates.p12 /tmp/'"
        run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chmod 644 /tmp/elastic-*.p12'"
        
        run_command "sshpass -p '$CERT_NODE_PASSWORD' scp -o StrictHostKeyChecking=no $CERT_NODE_IP:/tmp/elastic-stack-ca.p12 ./elastic-stack-ca.p12"
        run_command "sshpass -p '$CERT_NODE_PASSWORD' scp -o StrictHostKeyChecking=no $CERT_NODE_IP:/tmp/elastic-certificates.p12 ./elastic-certificates.p12"
        
        run_command "sshpass -p '$PASSWORD' scp -o StrictHostKeyChecking=no ./elastic-stack-ca.p12 $IP:/tmp/"
        run_command "sshpass -p '$PASSWORD' scp -o StrictHostKeyChecking=no ./elastic-certificates.p12 $IP:/tmp/"
        
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mv /tmp/elastic-*.p12 /home/elasticsearch/config/certs/'"
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch/config/certs'"
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chmod 640 /home/elasticsearch/config/certs/*.p12'"
        
        run_command "rm -f ./elastic-*.p12"
        run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo rm -f /tmp/elastic-*.p12'"
    fi
done

echo "==============================================================="
echo "PARTIE 6: SETTING UP PASSWORDS"
echo "==============================================================="

for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo cp /home/elasticsearch/config/elasticsearch.yml /home/elasticsearch/config/elasticsearch.yml.bak 2>/dev/null || echo \"No config to backup\"'"
    
    NODE_NAME=${NODE_HOSTNAMES["$IP"]}
    NODE_ROLES_PART=""
    if grep -q "node.roles" /home/elasticsearch/config/elasticsearch.yml.bak 2>/dev/null; then
        NODE_ROLES_PART="node.roles: [$NODE_ROLES_FORMATTED]"
    fi
    
    MINIMAL_CONFIG="cluster.name: $CLUSTER_NAME
node.name: $NODE_NAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
$NODE_ROLES_PART

xpack.security.enabled: false
xpack.security.transport.ssl.enabled: false
xpack.security.http.ssl.enabled: false
"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo bash -c \"echo \\\"$MINIMAL_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"
    
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl stop elasticsearch'"
done

sleep 10

for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl start elasticsearch'"
done

echo "Waiting 90 secs for elasticsearch service to restart without security..."
sleep 90

echo "Finding a working node..."
WORKING_NODE_IP=""

for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    
    PS_CHECK=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" "ps aux | grep elastic | grep -v grep | wc -l")
    if [ "$PS_CHECK" -eq "0" ]; then
        echo "bad news : ES not running on $IP!"
        continue
    fi
    
    HTTP_TEST=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" "curl -s http://$IP:9200/ || echo 'Failed'")
    
    if [[ "$HTTP_TEST" != *"Failed"* && "$HTTP_TEST" == *"You Know, for Search"* ]]; then
        echo "Found working node: $IP"
        WORKING_NODE_IP="$IP"
        WORKING_NODE_PASSWORD="${NODES[$IP]}"
        break
    else
        echo "node $IP not accessible via http"
    fi
done

if [ -z "$WORKING_NODE_IP" ]; then
    echo "No working nodes found. Using first node: ${NODE_IPS[0]}"
    WORKING_NODE_IP="${NODE_IPS[0]}"
    WORKING_NODE_PASSWORD="${NODES[$WORKING_NODE_IP]}"
fi

echo "Setting up passwords on $WORKING_NODE_IP..."

ELASTIC_PASSWORD="elastic"
KIBANA_PASSWORD="kibana"

run_command "sshpass -p '$WORKING_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $WORKING_NODE_IP 'cat > /tmp/setup_passwords.sh << \"EOF\"
#!/bin/bash
set -e

echo \"Testing cluster connection...\"
CLUSTER_TEST=$(curl -s http://'$WORKING_NODE_IP':9200/)
if [[ \"$CLUSTER_TEST\" != *\"You Know, for Search\"* ]]; then
    echo \"ERROR: Cannot connect to Elasticsearch! Response: $CLUSTER_TEST\"
    exit 1
fi

echo \"Setting elastic user password...\"
curl -X POST \"http://'$WORKING_NODE_IP':9200/_security/user/elastic/_password\" \
     -H \"Content-Type: application/json\" \
     -d '{\"password\": \"'$ELASTIC_PASSWORD'\"}' 

echo \"Setting kibana_system user password...\"
curl -X POST \"http://'$WORKING_NODE_IP':9200/_security/user/kibana_system/_password\" \
     -H \"Content-Type: application/json\" \
     -d '{\"password\": \"'$KIBANA_PASSWORD'\"}' 

for USER in apm_system beats_system logstash_system remote_monitoring_user; do
    echo \"Setting $USER password...\"
    curl -X POST \"http://'$WORKING_NODE_IP':9200/_security/user/$USER/_password\" \
         -H \"Content-Type: application/json\" \
         -d '{\"password\": \"'$ELASTIC_PASSWORD'\"}' 
done

echo \"Password setup complete!\"
EOF'"

run_command "sshpass -p '$WORKING_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $WORKING_NODE_IP 'chmod +x /tmp/setup_passwords.sh'"

echo "Running password setup script..."
PASSWORD_OUTPUT=$(sshpass -p "$WORKING_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no "$WORKING_NODE_IP" 'bash /tmp/setup_passwords.sh')
echo "$PASSWORD_OUTPUT"

if [[ "$PASSWORD_OUTPUT" == *"Password setup complete"* ]]; then
    echo "Password setup successful!"
else
    echo "Warning: password setup may have failed. continuing with defaults."
fi

echo "Saving password info..."
PASSWORD_INFO="Elasticsearch cluster passwords:
elastic: $ELASTIC_PASSWORD
kibana_system: $KIBANA_PASSWORD
All other users: $ELASTIC_PASSWORD"

run_command "sshpass -p '$WORKING_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $WORKING_NODE_IP \"sudo bash -c 'echo \\\"$PASSWORD_INFO\\\" > /home/elasticsearch/passwords.txt'\""
run_command "sshpass -p '$WORKING_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $WORKING_NODE_IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/passwords.txt 2>/dev/null || echo \"Could not change ownership\"'"
run_command "sshpass -p '$WORKING_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $WORKING_NODE_IP 'sudo chmod 600 /home/elasticsearch/passwords.txt 2>/dev/null || echo \"Could not change permissions\"'"

echo "Restoring secure config..."
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    
    BACKUP_EXISTS=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'if [ -f /home/elasticsearch/config/elasticsearch.yml.bak ]; then echo "yes"; else echo "no"; fi')
    
    if [ "$BACKUP_EXISTS" == "yes" ]; then
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo cp /home/elasticsearch/config/elasticsearch.yml.bak /home/elasticsearch/config/elasticsearch.yml'"
    else
        NODE_NAME=${NODE_HOSTNAMES["$IP"]}
        NODE_ROLES_PART=""
        if [ -n "$NODE_ROLES_FORMATTED" ]; then
            NODE_ROLES_PART="node.roles: [$NODE_ROLES_FORMATTED]"
        fi
        
        SECURE_CONFIG="cluster.name: $CLUSTER_NAME
node.name: $NODE_NAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
$NODE_ROLES_PART

xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: changeme
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: changeme

xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.http.ssl.keystore.password: changeme
xpack.security.http.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.http.ssl.truststore.password: changeme"

        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo bash -c \"echo \\\"$SECURE_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"
    fi
done

echo "Stopping all ES nodes..."
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl stop elasticsearch'"
done

sleep 10

echo "Starting nodes with security enabled..."
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl start elasticsearch'"
done

echo "Waiting 90 secs for secure cluster to start..."
sleep 90

echo "Checking cluster health..."
HEALTH_CHECK=$(sshpass -p "$WORKING_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no "$WORKING_NODE_IP" "curl -k -s -u elastic:$ELASTIC_PASSWORD https://$WORKING_NODE_IP:9200/_cluster/health || echo 'Failed'")

if [[ "$HEALTH_CHECK" != *"Failed"* && "$HEALTH_CHECK" == *"status"* ]]; then
    CLUSTER_STATUS=$(echo "$HEALTH_CHECK" | grep -o '"status":"[^"]*"' | cut -d '"' -f 4)
    echo "Cluster looks good! Status: $CLUSTER_STATUS"
else
    echo "Warning: couldn't check health. ur cluster might still be starting."
fi

echo "==============================================================="
echo "PARTIE 7: INSTALLING KIBANA WITH HTTPS"
echo "==============================================================="

echo "setting up Kibana on $KIBANA_IP..."

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'id -u elasticsearch &>/dev/null || sudo useradd elasticsearch -m -s /bin/bash'"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'if ! command -v java &> /dev/null; then sudo apt update && sudo apt install openjdk-17-jdk -y; else echo \"Java already installed.\"; fi'"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo mkdir -p /home/elasticsearch/config/certs/pem /var/log /var/run /home/kibana'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo touch /var/log/kibana.log'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch /var/log/kibana.log /var/run /home/kibana'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chmod 644 /var/log/kibana.log'"

run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo cp /home/elasticsearch/config/certs/elastic-stack-ca.p12 /tmp/'"
run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo cp /home/elasticsearch/config/certs/elastic-certificates.p12 /tmp/'"
run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chmod 644 /tmp/elastic-*.p12'"

run_command "sshpass -p '$CERT_NODE_PASSWORD' scp -o StrictHostKeyChecking=no $CERT_NODE_IP:/tmp/elastic-stack-ca.p12 ./elastic-stack-ca.p12"
run_command "sshpass -p '$CERT_NODE_PASSWORD' scp -o StrictHostKeyChecking=no $CERT_NODE_IP:/tmp/elastic-certificates.p12 ./elastic-certificates.p12"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' scp -o StrictHostKeyChecking=no ./elastic-stack-ca.p12 $KIBANA_IP:/tmp/"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' scp -o StrictHostKeyChecking=no ./elastic-certificates.p12 $KIBANA_IP:/tmp/"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo mv /tmp/elastic-*.p12 /home/elasticsearch/config/certs/'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch/config/certs'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chmod 640 /home/elasticsearch/config/certs/*.p12'"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo -u elasticsearch openssl pkcs12 -in /home/elasticsearch/config/certs/elastic-certificates.p12 -out /home/elasticsearch/config/certs/pem/kibana.crt -nokeys -clcerts -passin pass:$CERT_PASSWORD'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo -u elasticsearch openssl pkcs12 -in /home/elasticsearch/config/certs/elastic-certificates.p12 -out /home/elasticsearch/config/certs/pem/kibana.key -nocerts -nodes -passin pass:$CERT_PASSWORD'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo -u elasticsearch openssl pkcs12 -in /home/elasticsearch/config/certs/elastic-stack-ca.p12 -out /home/elasticsearch/config/certs/pem/ca.crt -nokeys -cacerts -passin pass:$CERT_PASSWORD'"

run_command "rm -f ./elastic-*.p12"
run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo rm -f /tmp/elastic-*.p12'"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'if [ ! -f kibana-8.17.3-linux-x86_64.tar.gz ]; then wget -q https://artifacts.elastic.co/downloads/kibana/kibana-8.17.3-linux-x86_64.tar.gz; fi'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'if [ ! -d kibana-8.17.3 ]; then tar -xzf kibana-8.17.3-linux-x86_64.tar.gz; fi'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo cp -rf kibana-8.17.3/* /home/kibana/'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chown -R elasticsearch:elasticsearch /home/kibana'"

IP_ARRAY=("${NODE_IPS[@]}")
ES_HOSTS=$(printf ",\"https://%s:9200\"" "${IP_ARRAY[@]}")
ES_HOSTS=${ES_HOSTS:1}

KIBANA_CONFIG="server.host: \"0.0.0.0\"
server.port: 5601

elasticsearch.hosts: [$ES_HOSTS]
elasticsearch.username: \"kibana_system\"
elasticsearch.password: \"$KIBANA_PASSWORD\"
elasticsearch.ssl.verificationMode: \"none\"
elasticsearch.ssl.certificateAuthorities: [\"/home/elasticsearch/config/certs/pem/ca.crt\"]

server.ssl.enabled: true
server.ssl.certificate: \"/home/elasticsearch/config/certs/pem/kibana.crt\"
server.ssl.key: \"/home/elasticsearch/config/certs/pem/kibana.key\"

logging.appenders.file.type: file
logging.appenders.file.fileName: \"/var/log/kibana.log\"
logging.appenders.file.layout.type: pattern
logging.root.appenders: [file]

telemetry.enabled: false
xpack.reporting.enabled: false
xpack.apm.ui.enabled: false"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo bash -c \"echo \\\"$KIBANA_CONFIG\\\" > /home/kibana/config/kibana.yml\"'"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo tee /etc/systemd/system/kibana.service > /dev/null << EOF
[Unit]
Description=Kibana
Documentation=https://www.elastic.co
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=elasticsearch
Group=elasticsearch
Environment="NODE_OPTIONS=--max-old-space-size=512"
ExecStart=/home/kibana/bin/kibana
Restart=always
WorkingDirectory=/home/kibana
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF'"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl daemon-reload'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl enable kibana'"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl stop kibana || true'"
sleep 5
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl start kibana'"

echo "waiting 60 secs for Kibana to start..."
sleep 60

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl status kibana --no-pager'"

KIBANA_HTTPS=$(sshpass -p "$KIBANA_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$KIBANA_IP" 'curl -k -I https://localhost:5601 2>/dev/null | head -1')
if [[ "$KIBANA_HTTPS" == *"200 OK"* || "$KIBANA_HTTPS" == *"302"* || "$KIBANA_HTTPS" == *"HTTP"* ]]; then
    echo "Kibana HTTPS works!"
else
    echo "Checking logs... Kibana HTTPS failed..."
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo tail -n 50 /var/log/kibana.log'"
fi

echo "==============================================================="
echo "PARTIE 8: FINAL CLUSTER CONFIG"
echo "==============================================================="

if [ ${#NODE_IPS[@]} -eq 1 ]; then
    echo "disabling shard replicas for single node setup..."
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'curl -k -X PUT \"https://$CERT_NODE_IP:9200/_cluster/settings\" -H \"Content-Type: application/json\" -u elastic:$ELASTIC_PASSWORD -d \"{\\\"persistent\\\": {\\\"index\\\": {\\\"number_of_replicas\\\": 0}}}\" || echo \"Could not set replicas, do it manually\"'"
fi

echo "============================================================="
echo "UR setup complete! ES and Kibana r running."
echo "============================================================="
echo "ES nodes: ${NODE_IPS[*]}"
echo "ES URL: https://${NODE_IPS[0]}:9200"
echo "Kibana URL: https://$KIBANA_IP:5601"
echo "Elastic user password: $ELASTIC_PASSWORD"
echo "Kibana system password: $KIBANA_PASSWORD"
echo "Cert password: $CERT_PASSWORD"
echo "============================================================="
echo "Notes:"
echo "- Certs in /home/elasticsearch/config/certs/"
echo "- Passwords saved in /home/elasticsearch/passwords.txt (if that goes well) on node $WORKING_NODE_IP"
echo "- to check cluster use this command curl -k -u elastic:password https://$WORKING_NODE_IP:9200/_cluster/health"
echo "============================================================="