#!/bin/bash

error_exit() {
    echo "err: $1" >&2
    exit 1
}

run_command() {
    eval "$1" || error_exit "failed: $1"
}

run_command_continue() {
    eval "$1" || echo "failed but continuing: $1"
}

if ! command -v sshpass &> /dev/null; then
    run_command "sudo apt update && sudo apt install sshpass -y"
else
    echo "sshpass alrdy installed"
fi

read -p "enter the number of Elasticsearch nodes: " NODE_COUNT
declare -A NODES
declare -a NODE_IPS
for ((i=1; i<=NODE_COUNT; i++)); do
    read -p "enter IP address for Node $i: " NODE_IP
    read -s -p "enter SSH password for Node $i: " SSH_PASSWORD
    echo
    NODES["$NODE_IP"]="$SSH_PASSWORD"
    NODE_IPS[$i-1]="$NODE_IP"
done
read -p "enter cluster name: " CLUSTER_NAME
read -p "enter Kibana IP: " KIBANA_IP
read -s -p "enter Kibana SSH password: " KIBANA_SSH_PASSWORD
echo
#ES
# /etc/hosts 
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
declare -A SAVED_NODE_ROLES_RAW
declare -A SAVED_NODE_ROLES_FORMATTED

for ((i=0; i<NODE_COUNT; i++)); do
    IP="${NODE_IPS[$i]}"
    PASSWORD=${NODES["$IP"]}
    HOSTNAME=${NODE_HOSTNAMES["$IP"]}
    echo "Setup: $HOSTNAME"

    # Java 
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'if ! command -v java &> /dev/null; then sudo apt update && sudo apt install openjdk-17-jdk -y; else echo \"java installed\"; fi'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'id -u elasticsearch &>/dev/null || sudo useradd elasticsearch -m -s /bin/bash'"

    # system limits
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'if [ ! -f /etc/security/limits.d/elasticsearch.conf ]; then sudo tee /etc/security/limits.d/elasticsearch.conf > /dev/null << EOF
elasticsearch soft nofile 65535
elasticsearch hard nofile 65535
elasticsearch soft nproc 4096
elasticsearch hard nproc 4096
EOF
else
    echo \"limits configured\"
fi'"

    # sysctl settings
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo sysctl -w vm.max_map_count=262144'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'grep -q \"vm.max_map_count=262144\" /etc/sysctl.conf || sudo bash -c \"echo vm.max_map_count=262144 >> /etc/sysctl.conf\"'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP '
if [ ! -f elasticsearch-8.17.3-linux-x86_64.tar.gz ]; then
    echo \"downloading...\"
    wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.3-linux-x86_64.tar.gz
    wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.3-linux-x86_64.tar.gz.sha512
    shasum -a 512 -c elasticsearch-8.17.3-linux-x86_64.tar.gz.sha512
else
    echo \"download exists\"
fi'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP '
if [ ! -d elasticsearch-8.17.3 ]; then
    echo \"Extracting...\"
    tar -xzf elasticsearch-8.17.3-linux-x86_64.tar.gz
else
    echo \"already extracted\"
fi'"
    
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /home/elasticsearch'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo cp -rf elasticsearch-8.17.3/* /home/elasticsearch/'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch'"
    # data n log directories with the correct permissions
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /var/lib/elasticsearch /var/log/elasticsearch'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chmod 755 /var/lib/elasticsearch /var/log/elasticsearch'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /var/lib/elasticsearch /var/log/elasticsearch'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /home/elasticsearch/config/jvm.options.d'" 
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /home/elasticsearch/config/certs'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch/config/certs'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chmod 755 /home/elasticsearch/config/certs'"

    # JVM
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo tee /home/elasticsearch/config/jvm.options.d/heap.options > /dev/null << EOF
-Xms1g
-Xmx1g
EOF'"
    read -p "Enter roles for $HOSTNAME comma separated (for ex master,data_content): " NODE_ROLES_INPUT 
    SAVED_NODE_ROLES_RAW["$IP"]="$NODE_ROLES_INPUT"
    NODE_ROLES=()
    IFS=',' read -ra NODE_ROLES <<< "$NODE_ROLES_INPUT"
    NODE_ROLES_FORMATTED=" ${NODE_ROLES[0]}"
    for ((j=1; j<${#NODE_ROLES[@]}; j++)); do
        NODE_ROLES_FORMATTED="$NODE_ROLES_FORMATTED, ${NODE_ROLES[$j]}"
    done
    NODE_ROLES_FORMATTED="$NODE_ROLES_FORMATTED "
    SAVED_NODE_ROLES_FORMATTED["$IP"]="$NODE_ROLES_FORMATTED"
    IP_ARRAY=( "${NODE_IPS[@]}" )
    SEED_HOSTS=$(printf ",\"%s\"" "${IP_ARRAY[@]}")
    SEED_HOSTS=${SEED_HOSTS:1}  
    HOSTNAME_ARRAY=()
    for NODE_IP in "${NODE_IPS[@]}"; do
        HOSTNAME_ARRAY+=("${NODE_HOSTNAMES[$NODE_IP]}")
    done
    MASTER_NODES=$(printf ",\"%s\"" "${HOSTNAME_ARRAY[@]}")
    MASTER_NODES=${MASTER_NODES:1}  
    SIMPLE_CONFIG="cluster.name: $CLUSTER_NAME
node.name: $HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]
xpack.security.enabled: false
xpack.security.transport.ssl.enabled: false
xpack.security.http.ssl.enabled: false
"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo bash -c \"echo \\\"$SIMPLE_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"
    # systemd service
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
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo rm -f /home/elasticsearch/config/elasticsearch.keystore'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl daemon-reload'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl enable elasticsearch'"
done
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl start elasticsearch'"
done
sleep 60
cluster_healthy=true
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    echo "Checking node $IP..."
    SERVICE_STATUS=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'sudo systemctl status elasticsearch --no-pager | grep "Active:"')
    echo "$SERVICE_STATUS"
    HTTP_TEST=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'curl -s http://$IP:9200/ || echo "HTTP test failed"')
    if [[ "$HTTP_TEST" == *"HTTP test failed"* ]]; then
        echo "HTTP failed on $IP"
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo tail -n 50 /var/log/elasticsearch/elasticsearch.log || echo \"no logs found\"'"
        cluster_healthy=false
    else
        echo "HTTP OK on $IP"
        echo "$HTTP_TEST"
    fi
done

if [ "$cluster_healthy" = false ]; then
    echo "not all the nodes are responding"
else
    echo "all nodes running"
fi
CERT_NODE_IP="${NODE_IPS[0]}"
CERT_NODE_PASSWORD=${NODES["$CERT_NODE_IP"]}
echo "generating certs on node $CERT_NODE_IP..."
CERT_PASSWORD="changeme"
echo "checking for existing certs..."
CERTS_EXIST=$(sshpass -p "$CERT_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no "$CERT_NODE_IP" 'if [ -f /home/elasticsearch/config/certs/elastic-stack-ca.p12 ] && [ -f /home/elasticsearch/config/certs/elastic-certificates.p12 ]; then echo "yes"; else echo "no"; fi')
if [ "$CERTS_EXIST" == "yes" ]; then
    echo "Certs exist. Use existing or generate new?"
    select cert_option in "use existing" "generate new"; do
        case $cert_option in
            "use existing")
                echo "Using existing certs"
                break
                ;;
            "generate new")
                
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo rm -f /home/elasticsearch/config/certs/elastic-stack-ca.p12 /home/elasticsearch/config/certs/elastic-certificates.p12'"
                
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-certutil ca --out /home/elasticsearch/config/certs/elastic-stack-ca.p12 --pass $CERT_PASSWORD'"

                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-certutil cert --ca /home/elasticsearch/config/certs/elastic-stack-ca.p12 --out /home/elasticsearch/config/certs/elastic-certificates.p12 --pass $CERT_PASSWORD --ca-pass $CERT_PASSWORD'"
                
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chmod 644 /home/elasticsearch/config/certs/*.p12'"
                run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/config/certs/*.p12'"
                break
                ;;
        esac
    done
else
    
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-certutil ca --out /home/elasticsearch/config/certs/elastic-stack-ca.p12 --pass $CERT_PASSWORD'"
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-certutil cert --ca /home/elasticsearch/config/certs/elastic-stack-ca.p12 --out /home/elasticsearch/config/certs/elastic-certificates.p12 --pass $CERT_PASSWORD --ca-pass $CERT_PASSWORD'" 
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chmod 644 /home/elasticsearch/config/certs/*.p12'"
    run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/config/certs/*.p12'"
fi
echo "distributing certs to other nodes..."
for IP in "${NODE_IPS[@]}"; do
    if [ "$IP" != "$CERT_NODE_IP" ]; then
        PASSWORD=${NODES["$IP"]}
        echo "Copying to $IP..."
        
        run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo cp /home/elasticsearch/config/certs/elastic-stack-ca.p12 /tmp/'"
        run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo cp /home/elasticsearch/config/certs/elastic-certificates.p12 /tmp/'"
        run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chmod 644 /tmp/elastic-*.p12'"  
        run_command "sshpass -p '$CERT_NODE_PASSWORD' scp -o StrictHostKeyChecking=no $CERT_NODE_IP:/tmp/elastic-stack-ca.p12 ./elastic-stack-ca.p12"
        run_command "sshpass -p '$CERT_NODE_PASSWORD' scp -o StrictHostKeyChecking=no $CERT_NODE_IP:/tmp/elastic-certificates.p12 ./elastic-certificates.p12"      
        run_command "sshpass -p '$PASSWORD' scp -o StrictHostKeyChecking=no ./elastic-stack-ca.p12 $IP:/tmp/"
        run_command "sshpass -p '$PASSWORD' scp -o StrictHostKeyChecking=no ./elastic-certificates.p12 $IP:/tmp/"  
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mv /tmp/elastic-*.p12 /home/elasticsearch/config/certs/'"
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/config/certs/*.p12'"
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chmod 644 /home/elasticsearch/config/certs/*.p12'"
        run_command "rm -f ./elastic-*.p12"
        run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo rm -f /tmp/elastic-*.p12'"
    fi
done
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    HOSTNAME=${NODE_HOSTNAMES["$IP"]}
    echo "Updating config on $HOSTNAME with transport SSL..."
    NODE_ROLES_FORMATTED="${SAVED_NODE_ROLES_FORMATTED["$IP"]}"
    SSL_CONFIG="cluster.name: $CLUSTER_NAME
node.name: $HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]
xpack.security.enabled: false
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: $CERT_PASSWORD
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: $CERT_PASSWORD
xpack.security.http.ssl.enabled: false"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo bash -c \"echo \\\"$SSL_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"
done
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl restart elasticsearch'"
done
echo "wait 90s for restart"
sleep 90
cluster_healthy=true
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    echo "Checking node $IP..."
    SERVICE_STATUS=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'sudo systemctl status elasticsearch --no-pager | grep "Active:"')
    echo "$SERVICE_STATUS" 
    HTTP_TEST=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'curl -s http://$IP:9200/ || echo "test failed"')
    if [[ "$HTTP_TEST" == *"HTTP test failed"* ]]; then
        echo "HTTP failed on $IP"
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo tail -n 50 /var/log/elasticsearch/elasticsearch.log || echo \"no logs found\"'"
        cluster_healthy=false
    else
        echo "http OK on $IP"
        echo "$HTTP_TEST"
    fi
done
if [ "$cluster_healthy" = false ]; then
    echo "not all nodes respondin"
else
    echo "all nodes running with transport ssl"
fi
HEALTH_CHECK=$(sshpass -p "${NODES["${NODE_IPS[0]}"]}" ssh -o StrictHostKeyChecking=no "${NODE_IPS[0]}" "curl -s http://${NODE_IPS[0]}:9200/_cluster/health || echo \"health check failed\"")
echo "Cluster health: $HEALTH_CHECK"
WORKING_NODE_IP="${NODE_IPS[0]}"
WORKING_NODE_PASSWORD=${NODES["$WORKING_NODE_IP"]}
run_command_continue "sshpass -p '$WORKING_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $WORKING_NODE_IP '
curl -X PUT \"http://$WORKING_NODE_IP:9200/_template/kibana_index_template\" -H \"Content-Type: application/json\" -d \"{
  \\\"index_patterns\\\": [\\\".kibana*\\\"],
  \\\"settings\\\": {
    \\\"number_of_shards\\\": 1,
    \\\"number_of_replicas\\\": 0,
    \\\"auto_expand_replicas\\\": \\\"0-1\\\"
  }
}\"'"

run_command_continue "sshpass -p '$WORKING_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $WORKING_NODE_IP '
curl -X PUT \"http://$WORKING_NODE_IP:9200/.kibana-1\" -H \"Content-Type: application/json\" -d \"{
  \\\"settings\\\": {
    \\\"number_of_shards\\\": 1,
    \\\"number_of_replicas\\\": 0
  }
}\"'"
run_command_continue "sshpass -p '$WORKING_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $WORKING_NODE_IP '
curl -X PUT \"http://$WORKING_NODE_IP:9200/.kibana-event-log-8.17.3-000001\" -H \"Content-Type: application/json\" -d \"{
  \\\"settings\\\": {
    \\\"number_of_shards\\\": 1,
    \\\"number_of_replicas\\\": 0
  }
}\"'"

sleep 10

echo "Checking cluster health"
HEALTH_CHECK=$(sshpass -p "${NODES["${NODE_IPS[0]}"]}" ssh -o StrictHostKeyChecking=no "${NODE_IPS[0]}" "curl -s http://${NODE_IPS[0]}:9200/_cluster/health")
echo "$HEALTH_CHECK"

FIRST_NODE_IP="${NODE_IPS[0]}"
FIRST_NODE_PASSWORD=${NODES["$FIRST_NODE_IP"]}
FIRST_NODE_HOSTNAME=${NODE_HOSTNAMES["$FIRST_NODE_IP"]}

NODE_ROLES_FORMATTED="${SAVED_NODE_ROLES_FORMATTED["$FIRST_NODE_IP"]}"

BASIC_SECURE_CONFIG="cluster.name: $CLUSTER_NAME
node.name: $FIRST_NODE_HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $FIRST_NODE_IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]

# basic sec, no HTTP SSL yet
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: $CERT_PASSWORD
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: $CERT_PASSWORD

xpack.security.http.ssl.enabled: false"

run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP 'sudo bash -c \"echo \\\"$BASIC_SECURE_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"

# Restart
run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP 'sudo systemctl restart elasticsearch'"
sleep 180
echo "configuring last node for password setup"
LAST_NODE_INDEX=$((NODE_COUNT-1))
LAST_NODE_IP="${NODE_IPS[$LAST_NODE_INDEX]}"
LAST_NODE_PASSWORD=${NODES["$LAST_NODE_IP"]}
LAST_NODE_HOSTNAME=${NODE_HOSTNAMES["$LAST_NODE_IP"]}
NODE_ROLES_FORMATTED="${SAVED_NODE_ROLES_FORMATTED["$LAST_NODE_IP"]}"
SECURE_CONFIG="cluster.name: $CLUSTER_NAME
node.name: $LAST_NODE_HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $LAST_NODE_IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: $CERT_PASSWORD
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: $CERT_PASSWORD

xpack.security.http.ssl.enabled: false"

run_command "sshpass -p \"$LAST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $LAST_NODE_IP 'sudo bash -c \"echo \\\"$SECURE_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"

# Restart and wait
run_command "sshpass -p \"$LAST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $LAST_NODE_IP 'sudo systemctl restart elasticsearch'"

echo "waiting 160s for last node restart"
sleep 160
FIRST_NODE_PASSWORD=${NODES["${NODE_IPS[0]}"]}
FIRST_OUTPUT=$(sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no ${NODE_IPS[0]} "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-setup-passwords interactive 2>&1" || echo "command failed")
if [[ "$FIRST_OUTPUT" == *"has already been changed"* ]]; then
    echo "passwords already set. will be using reset-password instead."
    echo "resetting elastic password:"
    sshpass -p "$FIRST_NODE_PASSWORD" ssh -t -o StrictHostKeyChecking=no ${NODE_IPS[0]} "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-reset-password -u elastic -i" || echo "reset completed"
    
    echo "Resetting kibana_system password:"
    sshpass -p "$FIRST_NODE_PASSWORD" ssh -t -o StrictHostKeyChecking=no ${NODE_IPS[0]} "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -i" || echo "Reset completed"
fi

# a lil wait between attempts
sleep 5
echo "Setting passwords on last node..."
LAST_OUTPUT=$(sshpass -p "$LAST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no $LAST_NODE_IP "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-setup-passwords interactive 2>&1" || echo "Command failed")
if [[ "$LAST_OUTPUT" == *"has already been changed"* ]]; then
    echo "Passwords already set. Using reset-password instead."
   
    sshpass -p "$LAST_NODE_PASSWORD" ssh -t -o StrictHostKeyChecking=no $LAST_NODE_IP "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-reset-password -u elastic -i" || echo "reset completed"
    
    sshpass -p "$LAST_NODE_PASSWORD" ssh -t -o StrictHostKeyChecking=no $LAST_NODE_IP "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -i" || echo "reset completed"
fi
read -p "enter 'elastic' password you set: " ELASTIC_PASSWORD
read -p "enter 'kibana_system' password you set: " KIBANA_PASSWORD
PASSWORD_INFO="es passwords:
elastic: $ELASTIC_PASSWORD
kibana_system: $KIBANA_PASSWORD"
run_command "sshpass -p \"$FIRST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP \"sudo bash -c 'echo \\\"$PASSWORD_INFO\\\" > /home/elasticsearch/passwords.txt'\""
run_command "sshpass -p \"$FIRST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/passwords.txt'"
run_command "sshpass -p \"$FIRST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP 'sudo chmod 600 /home/elasticsearch/passwords.txt'"
for ((i=0; i<NODE_COUNT; i++)); do
    IP="${NODE_IPS[$i]}"
    PASSWORD=${NODES["$IP"]}
    HOSTNAME=${NODE_HOSTNAMES["$IP"]}
    
    NODE_ROLES_FORMATTED="${SAVED_NODE_ROLES_FORMATTED["$IP"]}"
    
    NODE_FULL_SECURE_CONFIG="cluster.name: $CLUSTER_NAME
node.name: $HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]

# full sec with HTTPS
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: $CERT_PASSWORD
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: $CERT_PASSWORD

xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.http.ssl.keystore.password: $CERT_PASSWORD
xpack.security.http.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.http.ssl.truststore.password: $CERT_PASSWORD"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo bash -c \"echo \\\"$NODE_FULL_SECURE_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"
    
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl restart elasticsearch'"
done

sleep 180

HEALTH_CHECK=$(sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no "$FIRST_NODE_IP" "curl -k -u elastic:$ELASTIC_PASSWORD https://$FIRST_NODE_IP:9200/_cluster/health || echo 'maybe cluster needs more time or something wrong with the password'")
echo "Secure cluster health: $HEALTH_CHECK"
#Kibana
#user elasticsearch dans kibana
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'id -u elasticsearch &>/dev/null || sudo useradd elasticsearch -m -s /bin/bash'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'if ! command -v java &> /dev/null; then sudo apt update && sudo apt install openjdk-17-jdk -y; else echo \"Java installed\"; fi'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo mkdir -p /home/elasticsearch/config/certs'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chmod 755 /home/elasticsearch/config/certs'"
run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo cp /home/elasticsearch/config/certs/elastic-stack-ca.p12 /tmp/'"
run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo cp /home/elasticsearch/config/certs/elastic-certificates.p12 /tmp/'"
run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo chmod 644 /tmp/elastic-*.p12'"
run_command "sshpass -p '$CERT_NODE_PASSWORD' scp -o StrictHostKeyChecking=no $CERT_NODE_IP:/tmp/elastic-stack-ca.p12 ./elastic-stack-ca.p12"
run_command "sshpass -p '$CERT_NODE_PASSWORD' scp -o StrictHostKeyChecking=no $CERT_NODE_IP:/tmp/elastic-certificates.p12 ./elastic-certificates.p12"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' scp -o StrictHostKeyChecking=no ./elastic-stack-ca.p12 $KIBANA_IP:/tmp/"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' scp -o StrictHostKeyChecking=no ./elastic-certificates.p12 $KIBANA_IP:/tmp/"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo mv /tmp/elastic-*.p12 /home/elasticsearch/config/certs/'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/config/certs/*.p12'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chmod 644 /home/elasticsearch/config/certs/*.p12'"
run_command "rm -f ./elastic-*.p12"
run_command "sshpass -p '$CERT_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $CERT_NODE_IP 'sudo rm -f /tmp/elastic-*.p12'"
KIBANA_FILE_EXIST=$(sshpass -p "$KIBANA_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no "$KIBANA_IP" 'if [ -f kibana-8.17.3-linux-x86_64.tar.gz ]; then echo "yes"; else echo "no"; fi')

if [ "$KIBANA_FILE_EXIST" == "no" ]; then
    echo "downloading Kibana"
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/kibana/kibana-8.17.3-linux-x86_64.tar.gz'"
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/kibana/kibana-8.17.3-linux-x86_64.tar.gz.sha512'"
    
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'shasum -a 512 -c kibana-8.17.3-linux-x86_64.tar.gz.sha512'"
else
    echo "Kibana archive alrdy exists"
fi

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'rm -rf kibana-8.17.3 2>/dev/null'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'tar -xzf kibana-8.17.3-linux-x86_64.tar.gz'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo rm -rf /home/kibana'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo mkdir -p /home/kibana'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo cp -rf kibana-8.17.3/* /home/kibana/'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chown -R elasticsearch:elasticsearch /home/kibana'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo mkdir -p /var/log/kibana /var/run/kibana'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo rm -f /var/log/kibana/kibana.log'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo touch /var/log/kibana/kibana.log'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chown -R elasticsearch:elasticsearch /var/log/kibana /var/run/kibana'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chmod 755 /var/log/kibana /var/run/kibana'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chmod 664 /var/log/kibana/kibana.log'"

KIBANA_HTTPS_CONFIG="server.host: 0.0.0.0
server.port: 5601
elasticsearch.hosts: [\"https://$FIRST_NODE_IP:9200\"]
pid.file: /var/run/kibana/kibana.pid
server.publicBaseUrl: \"https://$KIBANA_IP:5601\"
xpack.reporting.enabled: false
# Auth
elasticsearch.username: \"kibana_system\"
elasticsearch.password: \"$KIBANA_PASSWORD\"
elasticsearch.ssl.verificationMode: \"none\"
elasticsearch.ssl.certificateAuthorities: [\"/home/elasticsearch/config/certs/elastic-stack-ca.p12\"]
# HTTPS
server.ssl.enabled: true
server.ssl.keystore.path: \"/home/elasticsearch/config/certs/elastic-certificates.p12\"
server.ssl.keystore.password: \"$CERT_PASSWORD\"
server.ssl.certificateAuthorities: [\"/home/elasticsearch/config/certs/elastic-stack-ca.p12\"]
xpack.encryptedSavedObjects.encryptionKey: \"fhjskloppd678ehkdfdlliverpoolfcr\""
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo bash -c \"echo \\\"$KIBANA_HTTPS_CONFIG\\\" > /home/kibana/config/kibana.yml\"'"
# systemd service 
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo tee /etc/systemd/system/kibana.service > /dev/null << EOF
[Unit]
Description=Kibana
Documentation=https://www.elastic.co
Wants=network-online.target
After=network-online.target

[Service]
User=elasticsearch
Group=elasticsearch
WorkingDirectory=/home/kibana
Environment=NODE_OPTIONS=--max-old-space-size=2048
ExecStart=/home/kibana/bin/kibana
StandardOutput=journal
StandardError=journal
LimitNOFILE=65535
TimeoutStartSec=600
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
EOF'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/config/certs/*.p12'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chmod 644 /home/elasticsearch/config/certs/*.p12'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl daemon-reload'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl stop kibana 2>/dev/null || echo \"kibana isn't running\"'"
sleep 10
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl start kibana'"
sleep 50
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl status kibana --no-pager || echo \"failed but maybe still just starting\"'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl enable kibana'"
echo -e "\n\n========== YOUR SUMMARY ==========\n"
echo "Elasticsearch nodes: ${NODE_IPS[*]}"
echo "Kibana URL: https://$KIBANA_IP:5601"
echo "passwords stored in: /home/elasticsearch/passwords.txt"
