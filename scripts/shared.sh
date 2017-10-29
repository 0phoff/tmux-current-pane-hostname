#!/usr/bin/env bash

# General functions
get_cmd_recursive() {
    local pid=$(tmux display-message -p '#{pane_pid}')
    local cmd=$(tmux display-message -p '#{pane_current_command}')

    # Docker/ssh was called directly
    if [[ $cmd = "docker" ]] || [[ $cmd = "ssh" ]] || [[ $cmd = "sshpass" ]]; then
        local cmd=$(pgrep -flaP $pid)
        local pid=$(echo $cmd | cut -d' ' -f1)
        echo "${cmd//$pid }"
        return
    fi

    # Recursively search for last command running
    local depth=0
    while [ -n "$pid" ] && [ "$depth" -lt "5" ]; do
        local prevcmd=${cmd//$pid }
        local cmd=$(pgrep -flaP $pid | tail -n1)
        local pid=$(echo $cmd | cut -d' ' -f1)
        ((++depth))
    done
    
    # return command
    echo "$prevcmd"
}


# Tmux functions
get_tmux_option() {
	local option=$1
	local default_value=$2
	local option_value=$(tmux show-option -gqv "$option")
	if [ -z "$option_value" ]; then
		echo "$default_value"
	else
		echo "$option_value"
	fi
}

set_tmux_option() {
	local option=$1
	local value=$2
	tmux set-option -gq "$option" "$value"
}


# SSH functions
parse_ssh_port() {
  # If there is a port get it
  local port=$(echo $1|grep -Eo '\-p ([0-9]+)'|sed 's/-p //')

  if [ -z $port ]; then
    local port=22
  fi

  echo $port
}

get_ssh_user() {
  local ssh_user=$(whoami)

  for ssh_config in `awk '
    $1 == "Host" {
      gsub("\\\\.", "\\\\.", $2);
      gsub("\\\\*", ".*", $2);
      host = $2;
      next;
    }
    $1 == "User" {
      $1 = "";
      sub( /^[[:space:]]*/, "" );
      printf "%s|%s\n", host, $0;
    }' .ssh/config`; do
    local host_regex=${ssh_config%|*}
    local host_user=${ssh_config#*|}
    if [[ "$1" =~ $host_regex ]]; then
      ssh_user=$host_user
      break
    fi
  done

  echo $ssh_user
}

get_remote_info() {
    local query=$1
    local command=$2

    # get arguments from command
    local args=$(echo $command | sed -E 's/^[0-9]*[[:blank:]]*ssh //')

    # Get host, user, port
    local port=$(parse_ssh_port "$args")
    local args=$(echo $args|sed 's/\-p '"$port"'//g')
    local user=$(echo $args | awk '{print $NF}'|cut -f1 -d@)
    local host=$(echo $args | awk '{print $NF}'|cut -f2 -d@)
    if [ $user == $host ]; then
        local user=$(get_ssh_user $host)
    fi

    # React to correct query
    case "$query" in
        "whoami")
            echo $user
            ;;
        "hostname")
            echo $host
            ;;
        *)
            echo "$user@$host:$port"
            ;;
    esac
}


# Docker functions
get_docker_info() {
    local query=$1
    local cmd=$2

    # Get container name
    local container=$(echo $cmd | grep -oe '--name \w*' | cut -d' ' -f2)

    # No docker name given or tty not connected
    if [ -z "$container" ] || [ "$(docker inspect --format='{{.Config.Tty}}' $container)" = "false" ]; then
        echo $($1)
        return
    fi

    # Get container info
    local host=$(docker inspect --format='{{.Config.Hostname}}' $container) 
    local user=$(docker inspect --format='{{.Config.User}}' $container)
    if [ -z "$user" ]; then
        local user='root'
    fi

    # react to query
    case "$query" in
        "whoami")
            echo "$user"
            ;;
        "hostname")
            echo "$host"
            ;;
        *)
            echo "$container:$user@$host"
            ;;
    esac
}


# Main function
get_info() {
    # Get current pane command and pid
    local cmd=$(get_cmd_recursive)

    # Check if command is ssh/docker
    if [[ $cmd = "ssh"* ]]; then
        echo $(get_remote_info $1 "$cmd")
    elif [[ $cmd = "docker"* ]]; then
        echo $(get_docker_info $1 "$cmd")
    else
        echo $($1)
    fi
}
