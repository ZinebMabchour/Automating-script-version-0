#!/bin/bash

error_exit() {
    echo "Error: $1" >&2
    exit 1
}

run_command() {
    echo "Running: $1"
    eval "$1" || error_exit "Command failed: $1"
}

run_command_continue() {
    echo "Running (non-critical): $1"
    eval "$1" || echo "Command failed but continuing: $1"
}

if ! command -v sshpass &> /dev/null; then
    echo "sshpass not found. Installing..."
    run_command "sudo apt update && sudo apt install sshpass -y"
else
    echo "sshpass already installed, skipping."
fi

# ----- USER INPUT SECTION (KEPT AT THE BEGINNING) -----
read -p "Enter the number of Elasticsearch nodes: " NODE_COUNT
declare -A NODES
declare -a NODE_IPS

for ((i=1; i<=NODE_COUNT; i++)); do
    read -p "Enter IP address for Node $i: " NODE_IP
    read -s -p "Enter SSH password for Node $i: " SSH_PASSWORD
    echo
    NODES["$NODE_IP"]="$SSH_PASSWORD"
    NODE_IPS[$i-1]="$NODE_IP"
done

read -p "enter your cluster name: " CLUSTER_NAME
read -p "enter the IP for Kibana: " KIBANA_IP
read -s -p "enter ssh password for Kibana: " KIBANA_SSH_PASSWORD
echo

# ----- ELASTICSEARCH SETUP SECTION -----
# /etc/hosts config
echo "Configuring /etc/hosts on all nodes..."
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
    echo "Setting up Elasticsearch on $HOSTNAME ($IP)..."

    # Java
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'if ! command -v java &> /dev/null; then sudo apt update && sudo apt install openjdk-17-jdk -y; else echo \"Java already installed, skipping.\"; fi'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'id -u elasticsearch &>/dev/null || sudo useradd elasticsearch -m -s /bin/bash'"

    # system limits
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'if [ ! -f /etc/security/limits.d/elasticsearch.conf ]; then sudo tee /etc/security/limits.d/elasticsearch.conf > /dev/null << EOF
elasticsearch soft nofile 65535
elasticsearch hard nofile 65535
elasticsearch soft nproc 4096
elasticsearch hard nproc 4096
EOF
else
    echo \"already configured..skipping.\"
fi'"

    # sysctl settings
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo sysctl -w vm.max_map_count=262144'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'grep -q \"vm.max_map_count=262144\" /etc/sysctl.conf || sudo bash -c \"echo vm.max_map_count=262144 >> /etc/sysctl.conf\"'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP '
if [ ! -f elasticsearch-8.17.3-linux-x86_64.tar.gz ]; then
    echo \"Downloading Elasticsearch...\"
    wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.3-linux-x86_64.tar.gz
    wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.3-linux-x86_64.tar.gz.sha512
    shasum -a 512 -c elasticsearch-8.17.3-linux-x86_64.tar.gz.sha512
else
    echo \"elasticsearch already downloaded in the server.\"
fi'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP '
if [ ! -d elasticsearch-8.17.3 ]; then
    echo \"Extracting Elasticsearch...\"
    tar -xzf elasticsearch-8.17.3-linux-x86_64.tar.gz
else
    echo \"elasticsearch already extracted on thiis server.\"
fi'"


    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /home/elasticsearch'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo cp -rf elasticsearch-8.17.3/* /home/elasticsearch/'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch'"

    # data n log directories with the correct permissions
    echo "Creating data and log directories with proper permissions..."
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /var/lib/elasticsearch /var/log/elasticsearch'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chmod 755 /var/lib/elasticsearch /var/log/elasticsearch'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /var/lib/elasticsearch /var/log/elasticsearch'"


    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /home/elasticsearch/config/jvm.options.d'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo mkdir -p /home/elasticsearch/config/certs'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch/config/certs'"
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo chmod 755 /home/elasticsearch/config/certs'"

    # JVM
    echo "Configuring jvm.options..."
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo tee /home/elasticsearch/config/jvm.options.d/heap.options > /dev/null << EOF
-Xms1g
-Xmx1g
EOF'"


    read -p "Enter roles for $HOSTNAME (make sure comma,separated: " NODE_ROLES_INPUT

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
    SEED_HOSTS=${SEED_HOSTS:1}  # Remove the leading comma


    HOSTNAME_ARRAY=()
    for NODE_IP in "${NODE_IPS[@]}"; do
        HOSTNAME_ARRAY+=("${NODE_HOSTNAMES[$NODE_IP]}")
    done
    MASTER_NODES=$(printf ",\"%s\"" "${HOSTNAME_ARRAY[@]}")
    MASTER_NODES=${MASTER_NODES:1}  # Remove the leading comma


    SIMPLE_CONFIG="# Basic cluster configuration
cluster.name: $CLUSTER_NAME
node.name: $HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]

# disable security completely for ur initial setup
xpack.security.enabled: false
xpack.security.transport.ssl.enabled: false
xpack.security.http.ssl.enabled: false
"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo bash -c \"echo \\\"$SIMPLE_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"

    # systemd service
    echo "Configuring systemd service..."
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


echo "Starting Elasticsearch on all nodes with minimal configuration..."
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    echo "Starting Elasticsearch on node $IP..."
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl start elasticsearch'"
done

echo "Waiting 60 seconds for Elasticsearch to start up with minimal configuration..."
sleep 60

# check if Elasticsearch is running on all the nodes

cluster_healthy=true
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    echo "Checking Elasticsearch status on node $IP..."
    SERVICE_STATUS=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'sudo systemctl status elasticsearch --no-pager | grep "Active:"')
    echo "Service status: $SERVICE_STATUS"


    HTTP_TEST=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'curl -s http://$IP:9200/ || echo "HTTP test failed"')
    if [[ "$HTTP_TEST" == *"HTTP test failed"* ]]; then
        echo "HTTP test failed on $IP."
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo tail -n 50 /var/log/elasticsearch/elasticsearch.log || echo \"No logs found\"'"
        cluster_healthy=false
    else
        echo "HTTP access successful on $IP"
        echo "$HTTP_TEST"
    fi
done

if [ "$cluster_healthy" = false ]; then
    echo "not all nodes are responding properly. will continue but u may need to troubleshoot."
else
    echo "All nodes up and running"
fi


# Generate certifs on the first node

CERT_NODE_IP="${NODE_IPS[0]}"
CERT_NODE_PASSWORD=${NODES["$CERT_NODE_IP"]}
echo "Generating certificates on node $CERT_NODE_IP..."

CERT_PASSWORD="changeme"

echo "Checking for existing certificates..."
CERTS_EXIST=$(sshpass -p "$CERT_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no "$CERT_NODE_IP" 'if [ -f /home/elasticsearch/config/certs/elastic-stack-ca.p12 ] && [ -f /home/elasticsearch/config/certs/elastic-certificates.p12 ]; then echo "yes"; else echo "no"; fi')

if [ "$CERTS_EXIST" == "yes" ]; then
    echo "certificates already exist. Do you want to use the existing or generate new ones?"
    select cert_option in "use existing" "generate new"; do
        case $cert_option in
            "use existing")
                echo "Using existing certificates..."
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

echo "Distributing certificates to nodes..."
for IP in "${NODE_IPS[@]}"; do
    if [ "$IP" != "$CERT_NODE_IP" ]; then
        PASSWORD=${NODES["$IP"]}
        echo "copying certificates to node $IP..."

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
    echo "Updating Elasticsearch configuration on $HOSTNAME ($IP) with transport SSL..."

    NODE_ROLES_FORMATTED="${SAVED_NODE_ROLES_FORMATTED["$IP"]}"

    SSL_CONFIG="# Basic cluster configuration
cluster.name: $CLUSTER_NAME
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

# Restart Elasticsearch
echo "Restarting Elasticsearch on all nodes with transport SSL..."
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    echo "Restarting Elasticsearch on node $IP..."
    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl restart elasticsearch'"
done

echo "waiting 90 seconds for Elasticsearch to restart with transport SSL..."
sleep 90

echo "Checking if Elasticsearch is running on all nodes with transport SSL..."
cluster_healthy=true
for IP in "${NODE_IPS[@]}"; do
    PASSWORD=${NODES["$IP"]}
    echo "Checking Elasticsearch status on node $IP..."
    SERVICE_STATUS=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'sudo systemctl status elasticsearch --no-pager | grep "Active:"')
    echo "Service status: $SERVICE_STATUS"

    HTTP_TEST=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$IP" 'curl -s http://$IP:9200/ || echo "HTTP test failed"')
    if [[ "$HTTP_TEST" == *"HTTP test failed"* ]]; then
        echo "HTTP test failed on $IP."
        run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo tail -n 50 /var/log/elasticsearch/elasticsearch.log || echo \"No logs found\"'"
        cluster_healthy=false
    else
        echo "HTTP access successful on $IP"
        echo "$HTTP_TEST"
    fi
done

if [ "$cluster_healthy" = false ]; then
    echo "not all nodes are responding properly. will continue with working nodes."
else
    echo "all nodes are up and running with transport SSL!"
fi

echo "Checking cluster health..."
HEALTH_CHECK=$(sshpass -p "${NODES["${NODE_IPS[0]}"]}" ssh -o StrictHostKeyChecking=no "${NODE_IPS[0]}" "curl -s http://${NODE_IPS[0]}:9200/_cluster/health || echo \"Health check failed\"")
echo "Cluster health: $HEALTH_CHECK"

# initial kibana indices
WORKING_NODE_IP="${NODE_IPS[0]}"
WORKING_NODE_PASSWORD=${NODES["$WORKING_NODE_IP"]}

echo "creatin Kibana index template..."
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


echo "creatin Kibana event log index"
run_command_continue "sshpass -p '$WORKING_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $WORKING_NODE_IP '
curl -X PUT \"http://$WORKING_NODE_IP:9200/.kibana-event-log-8.17.3-000001\" -H \"Content-Type: application/json\" -d \"{
  \\\"settings\\\": {
    \\\"number_of_shards\\\": 1,
    \\\"number_of_replicas\\\": 0
  }
}\"'"

# Wait
sleep 10

echo "checking cluster health..."
HEALTH_CHECK=$(sshpass -p "${NODES["${NODE_IPS[0]}"]}" ssh -o StrictHostKeyChecking=no "${NODE_IPS[0]}" "curl -s http://${NODE_IPS[0]}:9200/_cluster/health")
echo "cluster health: $HEALTH_CHECK"

echo "enabling basic security on the first node (${NODE_IPS[0]}) to use it to set passwords ,no https yet"
FIRST_NODE_IP="${NODE_IPS[0]}"
FIRST_NODE_PASSWORD=${NODES["$FIRST_NODE_IP"]}
FIRST_NODE_HOSTNAME=${NODE_HOSTNAMES["$FIRST_NODE_IP"]}

NODE_ROLES_FORMATTED="${SAVED_NODE_ROLES_FORMATTED["$FIRST_NODE_IP"]}"

BASIC_SECURE_CONFIG="# Basic cluster configuration
cluster.name: $CLUSTER_NAME
node.name: $FIRST_NODE_HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $FIRST_NODE_IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]

# Security settings - basic security only
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: $CERT_PASSWORD
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: $CERT_PASSWORD

# Keep HTTP without SSL for now
xpack.security.http.ssl.enabled: false"

run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP 'sudo bash -c \"echo \\\"$BASIC_SECURE_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"

# Restart
run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP 'sudo systemctl restart elasticsearch'"

# Wait
sleep 180

# --- PASSWORD SECTION WITH RESET FALLBACK ---

# Configure the LAST node properly first
echo "Configuring the last node for password setup..."
LAST_NODE_INDEX=$((NODE_COUNT-1))
LAST_NODE_IP="${NODE_IPS[$LAST_NODE_INDEX]}"
LAST_NODE_PASSWORD=${NODES["$LAST_NODE_IP"]}
LAST_NODE_HOSTNAME=${NODE_HOSTNAMES["$LAST_NODE_IP"]}

NODE_ROLES_FORMATTED="${SAVED_NODE_ROLES_FORMATTED["$LAST_NODE_IP"]}"

# Configure last node with proper settings
SECURE_CONFIG="# Basic cluster configuration
cluster.name: $CLUSTER_NAME
node.name: $LAST_NODE_HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $LAST_NODE_IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]

# Security settings - keep transport SSL enabled
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: $CERT_PASSWORD
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: $CERT_PASSWORD

# Keep HTTP without SSL
xpack.security.http.ssl.enabled: false"

run_command "sshpass -p \"$LAST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $LAST_NODE_IP 'sudo bash -c \"echo \\\"$SECURE_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"

# Restart and wait
run_command "sshpass -p \"$LAST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $LAST_NODE_IP 'sudo systemctl restart elasticsearch'"

echo "Waiting 180 seconds for the last node to restart with security enabled..."
sleep 180

# Get first node password
FIRST_NODE_PASSWORD=${NODES["${NODE_IPS[0]}"]}

# Capture and check the first node attempt
echo "Attempting password setup on first node ${NODE_IPS[0]}..."
FIRST_OUTPUT=$(sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no ${NODE_IPS[0]} "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-setup-passwords interactive 2>&1" || echo "Command failed")

# Check if we got the "password already changed" error
if [[ "$FIRST_OUTPUT" == *"has already been changed"* ]]; then
    echo "Detected that passwords have already been set. Using reset-password on first node instead."
    echo "Resetting elastic user password on first node:"
    sshpass -p "$FIRST_NODE_PASSWORD" ssh -t -o StrictHostKeyChecking=no ${NODE_IPS[0]} "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-reset-password -u elastic -i -f" || echo "Reset command completed"

    echo "Resetting kibana_system user password on first node:"
    sshpass -p "$FIRST_NODE_PASSWORD" ssh -t -o StrictHostKeyChecking=no ${NODE_IPS[0]} "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -i -f" || echo "Reset command completed"
fi

# Always wait between attempts
sleep 40

# Always try last node, also with reset fallback
echo "Attempting password setup on last node ${LAST_NODE_IP}..."
LAST_OUTPUT=$(sshpass -p "$LAST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no $LAST_NODE_IP "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-setup-passwords interactive 2>&1" || echo "Command failed")

# Check if we got the "password already changed" error on last node
if [[ "$LAST_OUTPUT" == *"has already been changed"* ]]; then
    echo "Detected that passwords have already been set. Using reset-password on last node instead."
    echo "Resetting elastic user password on last node:"
    sshpass -p "$LAST_NODE_PASSWORD" ssh -t -o StrictHostKeyChecking=no $LAST_NODE_IP "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-reset-password -u elastic -i -f" || echo "Reset command completed"

    echo "Resetting kibana_system user password on last node:"
    sshpass -p "$LAST_NODE_PASSWORD" ssh -t -o StrictHostKeyChecking=no $LAST_NODE_IP "sudo -u elasticsearch /home/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -i -f" || echo "Reset command completed"
fi

# Ask for the passwords after both attempts
read -p "Please enter the 'elastic' password you set: " ELASTIC_PASSWORD
read -p "Please enter the 'kibana_system' password you set: " KIBANA_PASSWORD

# Store passwords
PASSWORD_INFO="Elasticsearch cluster passwords:
elastic: $ELASTIC_PASSWORD
kibana_system: $KIBANA_PASSWORD"

run_command "sshpass -p \"$FIRST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP \"sudo bash -c 'echo \\\"$PASSWORD_INFO\\\" > /home/elasticsearch/passwords.txt'\""
run_command "sshpass -p \"$FIRST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP 'sudo chown elasticsearch:elasticsearch /home/elasticsearch/passwords.txt'"
run_command "sshpass -p \"$FIRST_NODE_PASSWORD\" ssh -o StrictHostKeyChecking=no $FIRST_NODE_IP 'sudo chmod 600 /home/elasticsearch/passwords.txt'"
# --- END OF PASSWORD SECTION ---

# https
echo "https all nodes"
for ((i=0; i<NODE_COUNT; i++)); do
    IP="${NODE_IPS[$i]}"
    PASSWORD=${NODES["$IP"]}
    HOSTNAME=${NODE_HOSTNAMES["$IP"]}

    echo "Enabling full security with https on node $HOSTNAME ($IP)..."

    NODE_ROLES_FORMATTED="${SAVED_NODE_ROLES_FORMATTED["$IP"]}"

    NODE_FULL_SECURE_CONFIG="# Basic cluster configuration
cluster.name: $CLUSTER_NAME
node.name: $HOSTNAME
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: $IP
http.port: 9200
transport.port: 9300
discovery.seed_hosts: [$SEED_HOSTS]
cluster.initial_master_nodes: [$MASTER_NODES]
node.roles: [$NODE_ROLES_FORMATTED]

# Security settings
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: $CERT_PASSWORD
xpack.security.transport.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: $CERT_PASSWORD

# HTTPS
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/elastic-certificates.p12
xpack.security.http.ssl.keystore.password: $CERT_PASSWORD
xpack.security.http.ssl.truststore.path: certs/elastic-certificates.p12
xpack.security.http.ssl.truststore.password: $CERT_PASSWORD"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo bash -c \"echo \\\"$NODE_FULL_SECURE_CONFIG\\\" > /home/elasticsearch/config/elasticsearch.yml\"'"

    run_command "sshpass -p '$PASSWORD' ssh -o StrictHostKeyChecking=no $IP 'sudo systemctl restart elasticsearch'"
done

sleep 180

# Check Elasticsearch secure health before proceeding to Kibana
HEALTH_CHECK=$(sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no "$FIRST_NODE_IP" "curl -k -u elastic:$ELASTIC_PASSWORD https://$FIRST_NODE_IP:9200/_cluster/health || echo 'Health check may need a moment longer...'")
echo "Secure cluster health: $HEALTH_CHECK"

# ----- KIBANA SETUP SECTION (ALL TOGETHER AFTER ELASTICSEARCH) -----
echo -e "\n\n========== STARTING KIBANA SETUP ==========\n"

echo "Setting up Kibana on $KIBANA_IP..."

echo "Creating elasticsearch user on Kibana server"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'id -u elasticsearch &>/dev/null || sudo useradd elasticsearch -m -s /bin/bash'"

echo "checking Java on Kibana server..."
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'if ! command -v java &> /dev/null; then sudo apt update && sudo apt install openjdk-17-jdk -y; else echo \"Java already installed, skipping.\"; fi'"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo mkdir -p /home/elasticsearch/config/certs'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chown -R elasticsearch:elasticsearch /home/elasticsearch'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo chmod 755 /home/elasticsearch/config/certs'"

echo "Copying certificates to Kibana server "

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
    echo "Downloading Kibana..."
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/kibana/kibana-8.17.3-linux-x86_64.tar.gz'"
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'wget -t 5 -q --show-progress https://artifacts.elastic.co/downloads/kibana/kibana-8.17.3-linux-x86_64.tar.gz.sha512'"

    # verify download
    run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'shasum -a 512 -c kibana-8.17.3-linux-x86_64.tar.gz.sha512'"
else
    echo "Kibana archive already exists."
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

# Note: After enabling HTTPS on Elasticsearch, use HTTPS in Kibana config
KIBANA_HTTPS_CONFIG="server.host: 0.0.0.0
server.port: 5601
elasticsearch.hosts: [\"https://$FIRST_NODE_IP:9200\"]
pid.file: /var/run/kibana/kibana.pid
server.publicBaseUrl: \"https://$KIBANA_IP:5601\"
xpack.reporting.enabled: false

# Authentication for Elasticsearch with HTTPS
elasticsearch.username: \"kibana_system\"
elasticsearch.password: \"$KIBANA_PASSWORD\"
elasticsearch.ssl.verificationMode: \"none\"
elasticsearch.ssl.certificateAuthorities: [\"/home/elasticsearch/config/certs/elastic-stack-ca.p12\"]

# HTTPS
server.ssl.enabled: true
server.ssl.keystore.path: \"/home/elasticsearch/config/certs/elastic-certificates.p12\"
server.ssl.keystore.password: \"$CERT_PASSWORD\"
server.ssl.certificateAuthorities: [\"/home/elasticsearch/config/certs/elastic-stack-ca.p12\"]

# Encryption key for saved objects
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

echo "Reloading systemd and starting Kibana with HTTPS..."
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl daemon-reload'"
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl stop kibana 2>/dev/null || echo \"Kibana was not running\"'"
echo "Waiting 10 seconds for Kibana to fully stop and release resources..."
sleep 10

echo "Starting Kibana with HTTPS..."
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl start kibana'"
echo "Waiting 60 seconds for Kibana to start up with HTTPS..."
sleep 60

echo "Checking Kibana status..."
run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl status kibana --no-pager || echo \"Status check failed but it might still be starting\"'"

run_command "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_IP 'sudo systemctl enable kibana'"

# Summary of the installation
echo -e "\n\n========== INSTALLATION SUMMARY ==========\n"
echo "Elasticsearch nodes: ${NODE_IPS[*]}"
echo "Kibana is accessible at: https://$KIBANA_IP:5601"
echo "Elasticsearch passwords are stored in /home/elasticsearch/passwords.txt on node $FIRST_NODE_IP"
