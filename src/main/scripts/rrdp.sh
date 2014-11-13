EXECUTION_DIR=`dirname "$BASH_SOURCE"`
cd ${EXECUTION_DIR}

APP_NAME="rrdp"
PID_FILE=${APP_NAME}.pid

function error_exit {
    echo -e "[ error ] $1"
    exit 1
}

function info {
    echo -e "[ info ] $1"
}

function warn {
    echo -e "[ warn ] $1"
}

function usage {
cat << EOF
Usage: $0 start
   or  $0 run
   or  $0 stop
   or  $0 status
EOF
}

#
# Specify the location of the Java home directory. If set then $JAVA_CMD will
# be defined to $JAVA_HOME/bin/java
#
if [ -d "${JAVA_HOME}"  ] ; then
    JAVA_CMD="${JAVA_HOME}/bin/java"
else
    warn "JAVA_HOME is not set, will try to find java on path."
    JAVA_CMD=`which java`
fi

if [ -z $JAVA_CMD ]; then
    error_exit "Cannot find java on path. Make sure java is installed and/or set JAVA_HOME"
fi


# See how we're called
FIRST_ARG="$1"
shift
if [[ -n $MODE ]]; then
   usage
   exit
fi

# Determine config file location
getopts ":c:" OPT_NAME
CONFIG_FILE=${OPTARG:-conf/rrdp.conf}

if [[ ! $CONFIG_FILE =~ .*conf$ ]]; then
        error_exit "Configuration file name must end with .conf"
fi

if [[ ! -r $CONFIG_FILE ]]; then
    error_exit "Can't read config file: $CONFIG_FILE"
fi

function parse_optional_config_line {
    local CONFIG_KEY=$1
    local VALUE=`grep "^$CONFIG_KEY" $CONFIG_FILE | sed 's/#.*//g' | awk -F "=" '{ print $2 }'`
    eval "$2=$VALUE"
}

function parse_config_line {
    local CONFIG_KEY=$1
    local VALUE=`grep "^$CONFIG_KEY" $CONFIG_FILE | sed 's/#.*//g' | awk -F "=" '{ print $2 }'`

    if [ -z $VALUE ]; then
        error_exit "Cannot find value for: $CONFIG_KEY in config-file: $CONFIG_FILE"
    fi
    eval "$2=$VALUE"
}

function parse_jvm_options {
    parse_optional_config_line "jvm.proxy.socks.host" JVM_SOCKS_PROXY_HOST
    parse_optional_config_line "jvm.proxy.socks.port" JVM_SOCKS_PROXY_PORT

    parse_optional_config_line "jvm.proxy.http.host" JVM_HTTP_PROXY_HOST
    parse_optional_config_line "jvm.proxy.http.port" JVM_HTTP_PROXY_PORT

    JVM_OPTIONS="-Dapp.name=${APP_NAME} -Dconfig.file=$CONFIG_FILE"
    if [[ -n $JVM_SOCKS_PROXY_HOST && -n $JVM_SOCKS_PROXY_PORT ]]; then
        JVM_OPTIONS="$JVM_OPTIONS -DsocksProxyHost=$JVM_SOCKS_PROXY_HOST -DsocksProxyPort=$JVM_SOCKS_PROXY_PORT"
    elif [[ -n $JVM_HTTP_PROXY_HOST && -n $JVM_HTTP_PROXY_PORT ]]; then
        JVM_OPTIONS="$JVM_OPTIONS -Dhttp.proxyHost=$JVM_HTTP_PROXY_HOST -Dhttp.proxyPort=$JVM_HTTP_PROXY_PORT"
    fi
}

parse_config_line "rrdp.http.port" HTTP_PORT_VALUE

parse_config_line "locations.libdir" LIB_DIR
parse_config_line "locations.pidfile" PID_FILE

parse_config_line "jvm.memory.initial" JVM_XMS
parse_config_line "jvm.memory.maximum" JVM_XMX

parse_jvm_options

#
# Determine if the application is already running
#
RUNNING="false"
if [ -e ${PID_FILE} ]; then
    ps `cat ${PID_FILE}` | grep "\-Dapp.name=${APP_NAME}" >/dev/null 2>&1
    if [ $? == "0" ]; then
        RUNNING="true"
    fi
fi


case ${FIRST_ARG} in
    start)
        if [ ${RUNNING} == "true" ]; then
            error_exit "${APP_NAME} is already running"
        fi

        info "Starting ${APP_NAME}..."
        info "writing logs under log directory"
        info "Web user interface is available on port ${HTTP_PORT_VALUE}"

        CLASSPATH=:"$LIB_DIR/*"
        MEM_OPTIONS="-Xms$JVM_XMS -Xmx$JVM_XMX"

        nohup ${JAVA_CMD} ${JVM_OPTIONS} ${MEM_OPTIONS} ${JAVA_OPTS} \
             "-Dapp.name=${APP_NAME} -Dconfig.file=$CONFIG_FILE " \
              -classpath ${CLASSPATH} \
              nl.bruijnzeels.tim.rpki.rrdp.app.Main >/dev/null 2>&1 &
        RETCODE=$?


        PID=$!
        echo $PID > $PID_FILE
        info "Writing PID ${PID} to ${PID_FILE}"
        ;;
    stop)
        info "Stopping ${APP_NAME}..."
        if [ ${RUNNING} == "true" ]; then
            kill `cat ${PID_FILE}` && rm ${PID_FILE}
        else
            info "${APP_NAME} in not running"
        fi
        ;;
    status)
        if [ ${RUNNING} == "true" ]; then
            info "${APP_NAME} is running"
            exit 0
        else
            info "${APP_NAME} is not running"
            exit 0
        fi
        ;;
    *)
        usage
        exit
        ;;
esac

exit $?
