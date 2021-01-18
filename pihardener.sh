#!/bin/sh
#
# Raspberry Pi Hardener
#
# Raspberry Pi Hardener is an automated hardening tool for Raspberry Pi Raspbian operating system.
#
#################################################################################

# Program information
PROGRAM_NAME="Raspberry Pi Hardener"

# Version details
PROGRAM_VERSION="1.0"

# Currently supported systems
supported="Raspbian Buster"

# log file
log="run.log"

# file backups
moduli="/etc/ssh/moduli.min"
sshd_config_min="/etc/ssh/sshd_config.min"
sshd_config_high="/etc/ssh/sshd_config.high"
sshd_config_max="/etc/ssh/sshd_config.max"
sshd_config_paranoid="/etc/ssh/sshd_config.paranoid"
pamd_paranoid="/etc/pam.d/sshd"
sudoers_high="/etc/sudoers.d/010_pi-nopasswd.high"
sudoers_max="/etc/sudoers.d/010_pi-nopasswd.max"
sshpwd="/etc/profile.d/sshpwd.min"

#################################################################################
#
# Initialize and default settings
#
#################################################################################

cleanup () {
  # Reap all the spinners
  if [ ! -z "$allpids" ]; then
    for pid in $allpids; do
      kill "$pid" 1>/dev/null 2>&1
    done
    tput rc
  fi
  tput cnorm
  return 1
}

# This tries to catch any exit, whether normal or forced (e.g. Ctrl-C)
trap cleanup INT QUIT TERM EXIT

# scolors - Color constants
# canonical source http://github.com/swelljoe/scolors

# do we have tput?
if which 'tput' > /dev/null; then
  # do we have a terminal?
  if [ -t 1 ]; then
    # does the terminal have colors?
    ncolors=$(tput colors)
    if [ "$ncolors" -ge 8 ]; then
      RED=$(tput setaf 1)
      GREEN=$(tput setaf 2)
      YELLOW=$(tput setaf 3)
      BLUE=$(tput setaf 4)
      MAGENTA=$(tput setaf 5)
      CYAN=$(tput setaf 6)
      WHITE=$(tput setaf 7)
      REDBG=$(tput setab 1)
      GREENBG=$(tput setab 2)
      YELLOWBG=$(tput setab 3)
      BLUEBG=$(tput setab 4)
      MAGENTABG=$(tput setab 5)
      CYANBG=$(tput setab 6)
      WHITEBG=$(tput setab 7)

      BOLD=$(tput bold)
      UNDERLINE=$(tput smul) # Many terminals don't support this
      NORMAL=$(tput sgr0)
    fi
  fi
else
  echo "tput not found, colorized output disabled."
  RED=''
  GREEN=''
  YELLOW=''
  BLUE=''
  MAGENTA=''
  CYAN=''
  WHITE=''
  REDBG=''
  GREENBG=''
  YELLOWBG=''
  BLUEBG=''
  MAGENTABG=''
  CYANBG=''

  BOLD=''
  UNDERLINE=''
  NORMAL=''
fi

# Ask a yes or no question
yesno () {
  # XXX skipyesno is a global set in the calling script
  if [ "$skipyesno" = "1" ]; then
    return 0
  fi
  while read -r line; do
    case $line in
      y|Y|Yes|YES|yes|yES|yEs|YeS|yeS) return 0
      ;;
      n|N|No|NO|no|nO) return 1
      ;;
      *)
      printf "\\n${YELLOW}Please enter ${CYAN}[y]${YELLOW} or ${CYAN}[n]${YELLOW}:${NORMAL} "
      ;;
    esac
  done
}

# get os information
get_distro () {
  os=$(uname -o)
  # Make sure we're Linux
  if echo "$os" | grep -iq linux; then
    if [ -f /etc/redhat-release ]; then # RHEL/CentOS
      os_string=$(cat /etc/redhat-release)
      isrhel=$(echo "$os_string" | grep 'Red Hat')
      if [ ! -z "$isrhel" ]; then
        os_real='RHEL'
      else
        os_real=$(echo "$os_string" | cut -d' ' -f1) # Doesn't work for Scientific
      fi
      os_type=$(echo "$os_real" | tr '[:upper:]' '[:lower:]')
      os_version=$(echo "$os_string" | grep -o '[0-9\.]*')
      os_major_version=$(echo "$os_version" | cut -d '.' -f1)
    elif [ -f /etc/os-release ]; then # Debian/Ubuntu
      # Source it, so we can check VERSION_ID
      . /etc/os-release
      # Not technically correct, but os-release does not have 7.xxx for centos
      os_real=$NAME
      os_type=$ID
      os_version=$VERSION_ID
      os_major_version=$(echo "${os_version}" | cut -d'.' -f1)
    else
      printf "${RED}Fatal:${NORMAL} No /etc/*-release file found, this OS is probably not supported.${NORMAL}\\n"
      return 1
    fi
  else
    printf "${RED}Fatal:${NORMAL} Failed to detect a supported operating system.${NORMAL}\\n"
    return 1
  fi
  if [ ! -z "$1" ]; then
    case $1 in
      real)
        echo "$os_real"
        ;;
      type)
        echo "$os_type"
        ;;
      version)
        echo "$os_version"
        ;;
      major)
        echo "$os_major_version"
        ;;
      *)
        printf "${RED}Fatal:${NORMAL} Unknown argument.${NORMAL}\\n"
        return 1
        ;;
    esac
  fi
  return 0
}

# spinner - Log to provide spinners when long-running tasks happen
# Canonical source http://github.com/swelljoe/spinner

# Config variables, set these after sourcing to change behavior.
SPINNER_COLORNUM=2 # What color? Irrelevent if COLORCYCLE=1.
SPINNER_COLORCYCLE=1 # Does the color cycle?
SPINNER_DONEFILE="stopspinning" # Path/name of file to exit on.
SPINNER_SYMBOLS="ASCII_PROPELLER" # Name of the variable containing the symbols.
SPINNER_CLEAR=1 # Blank the line when done.

spinner () {
  # Safest option are one of these. Doesn't need Unicode, at all.
  local ASCII_PROPELLER="/ - \\ |"

  # Bigger spinners and progress type bars; takes more space.
  local WIDE_ASCII_PROG="[>----] [=>---] [==>--] [===>-] [====>] [----<] [---<=] [--<==] [-<===] [<====]"
  local WIDE_UNI_GREYSCALE="▒▒▒▒▒▒▒ █▒▒▒▒▒▒ ██▒▒▒▒▒ ███▒▒▒▒ ████▒▒▒ █████▒▒ ██████▒ ███████ ██████▒ █████▒▒ ████▒▒▒ ███▒▒▒▒ ██▒▒▒▒▒ █▒▒▒▒▒▒ ▒▒▒▒▒▒▒"
  local WIDE_UNI_GREYSCALE2="▒▒▒▒▒▒▒ █▒▒▒▒▒▒ ██▒▒▒▒▒ ███▒▒▒▒ ████▒▒▒ █████▒▒ ██████▒ ███████ ▒██████ ▒▒█████ ▒▒▒████ ▒▒▒▒███ ▒▒▒▒▒██ ▒▒▒▒▒▒█"

  local SPINNER_NORMAL
  SPINNER_NORMAL=$(tput sgr0)

  eval SYMBOLS=\$${SPINNER_SYMBOLS}

  # Get the parent PID
  SPINNER_PPID=$(ps -p "$$" -o ppid=)
  while :; do
    tput civis
    for c in ${SYMBOLS}; do
      if [ $SPINNER_COLORCYCLE -eq 1 ]; then
        if [ $SPINNER_COLORNUM -eq 7 ]; then
          SPINNER_COLORNUM=1
        else
          SPINNER_COLORNUM=$((SPINNER_COLORNUM+1))
        fi
      fi
      local SPINNER_COLOR
      SPINNER_COLOR=$(tput setaf ${SPINNER_COLORNUM})
      tput sc
      env printf "${SPINNER_COLOR}${c}${SPINNER_NORMAL}"
      tput rc
      if [ -f "${SPINNER_DONEFILE}" ]; then
        if [ ${SPINNER_CLEAR} -eq 1 ]; then
          tput el
        fi
	      rm -f ${SPINNER_DONEFILE}
	      break 2
      fi
      # This is questionable. sleep with fractional seconds is not
      # always available, but seems to not break things, when not.
      env sleep .2
      # Check to be sure parent is still going; handles sighup/kill
      if [ ! -z "$SPINNER_PPID" ]; then
        # This is ridiculous. ps prepends a space in the ppid call, which breaks
        # this ps with a "garbage option" error.
        # XXX Potential gotcha if ps produces weird output.
        SPINNER_PARENTUP=$(ps --no-headers $SPINNER_PPID)
        if [ -z "$SPINNER_PARENTUP" ]; then
          break 2
        fi
      fi
    done
  done
  tput rc
  tput cnorm
  return 0
}

# run_ok - function to run a command or function, start a spinner and print a confirmation
# indicator when done.
# Canonical source - http://github.com/swelljoe/run_ok
RUN_LOG="$log"
# Exit on any failure during shell stage
RUN_ERRORS_FATAL=1

# Check for unicode support in the shell
# This is a weird function, but seems to work. Checks to see if a unicode char can be
# written to a file and can be read back.
shell_has_unicode () {
  # Write a unicode character to a file...read it back and see if it's handled right.
  env printf "\\u2714"> unitest.txt

  read -r unitest < unitest.txt
  rm -f unitest.txt
  if [ ${#unitest} -le 3 ]; then
    return 0
  else
    return 1
  fi
}

# Setup spinner with our prefs.
SPINNER_COLORCYCLE=0
SPINNER_COLORNUM=6
if shell_has_unicode; then
  SPINNER_SYMBOLS="WIDE_UNI_GREYSCALE2"
else
  SPINNER_SYMBOLS="WIDE_ASCII_PROG"
fi
SPINNER_CLEAR=0 # Don't blank the line, so our check/x can simply overwrite it.

# Perform an action, and print a colorful checkmark or X if failed
# Returns 0 if successful, $? if failed.
run_ok () {
  # Shell is really clumsy with passing strings around.
  # This passes the unexpanded $1 and $2, so subsequent users get the
  # whole thing.
  local cmd="${1}"
  local msg="${2}"
  local columns
  columns=$(tput cols)
  if [ "$columns" -ge 80 ]; then
    columns=79
  fi
  COL=$((${columns}-${#msg}-7 ))

  printf "%s%${COL}s" "$2"
  # Make sure there some unicode action in the shell; there's no
  # way to check the terminal in a POSIX-compliant way, but terms
  # are mostly ahead of shells.
  # Unicode checkmark and x mark for run_ok function
  CHECK='\u2714'
  BALLOT_X='\u2718'
  spinner &
  spinpid=$!
  allpids="$allpids $spinpid"
  echo "Spin pid is: $spinpid" >> ${RUN_LOG}
  eval "${cmd}" 1>> ${RUN_LOG} 2>&1
  local res=$?
  touch ${SPINNER_DONEFILE}
  env sleep .2 # It's possible to have a race for stdout and spinner clobbering the next bit
  # Just in case the spinner survived somehow, kill it.
  pidcheck=$(ps --no-headers ${spinpid})
  if [ ! -z "$pidcheck" ]; then
    echo "Made it here...why?" >> ${RUN_LOG}
    kill $spinpid 2>/dev/null
    rm -rf ${SPINNER_DONEFILE} 2>/dev/null 2>&1
    tput rc
    tput cnorm
  fi
  # Log what we were supposed to be running
  printf "${msg}: " >> ${RUN_LOG}
  if shell_has_unicode; then
    if [ $res -eq 0 ]; then
      printf "Success.\\n" >> ${RUN_LOG}
      env printf "${GREENBG}[  ${CHECK}  ]${NORMAL}\\n"
      return 0
    else
      echo "Failed with error: ${res}"
      env printf "${REDBG}[  ${BALLOT_X}  ]${NORMAL}\\n"
      if [ "$RUN_ERRORS_FATAL" ]; then
        echo
        echo "Something went wrong. Exiting."
        echo "The last few log entries were:"
        tail -15 ${RUN_LOG}
		RemovePIDFile
        exit 1
      fi
      return ${res}
    fi
  else
    if [ $res -eq 0 ]; then
      printf "Success.\\n" >> ${RUN_LOG}
      env printf "${GREENBG}[ OK! ]${NORMAL}\\n"
      return 0
    else
      printf "Failed with error: ${res}\\n" >> ${RUN_LOG}
      echo
      env printf "${REDBG}[ERROR]${NORMAL}\\n"
      if [ "$RUN_ERRORS_FATAL" ]; then
        echo "Something went wrong with the previous command. Exiting."
		RemovePIDFile
        exit 1
      fi
      return ${res}
    fi
  fi
}

# adding the new user to the system
add_sudo_user() {
	egrep "^$USERNAME" /etc/passwd >/dev/null
		if [ $? -eq 0 ]; then
			echo "${RED}Fatal:${NORMAL} username is empty or already exists.${NORMAL}"; res=1
		else
			pass=$(perl -e 'print crypt($ARGV[0], "password")' $PASSWORD)
			useradd -G sudo -m -p $pass $USERNAME
			if [ $? -eq 0 ]; then
				echo "$USERNAME has been added to system!"
			else
				echo "${RED}Fatal:${NORMAL} An error occured when adding $USERNAME to the system.${NORMAL}"; res=2
			fi
		fi
	return ${res}
}

# Generates a memorable password of 2 words + 2 numbers (all lower key)
generate_memorable_password() {
	PASSWORD=$(xkcdpass -d '' -n 2)$(shuf -i 0-99 -n 1)
}

wget_check () {
	# Check for wget or curl or fetch
	while true; do
	  if [ -x "/usr/bin/wget" ]; then
		download="/usr/bin/wget -nv"
		break
	  elif [ -x "/usr/bin/curl" ]; then
		download="/usr/bin/curl -f -s -L -O"
		break
	  elif [ -x "/usr/bin/fetch" ]; then
		download="/usr/bin/fetch"
		break
	  elif [ "$wget_attempted" = 1 ]; then
		printf "${RED}No HTTP client available. Could not install wget. Cannot continue.${NORMAL}\\n"
		RemovePIDFile
		exit 1
	  fi

	  # Made it here without finding a downloader, so try to install one
	  wget_attempted=1
	  if [ -x /usr/bin/dnf ]; then
		dnf -y install wget
	  elif [ -x /usr/bin/yum ]; then
		yum -y install wget
	  elif [ -x /usr/bin/apt-get ]; then
		apt-get update >> /dev/null
		apt-get -y -q install wget
	  fi
	done
	if [ -z "$download" ]; then
	  echo "Tried to install downloader, but failed. Do you have working network and DNS?"
	fi
}

# download()
# Use $download to download the provided filename or exit with an error.
download() {
  # XXX Check this to make sure run_ok is doing the right thing.
  # Especially make sure failure gets logged right.
  # awk magic prints the filename, rather than whole URL
  download_file=$(echo "$1" |awk -F/ '{print $NF}')
  run_ok "$download $1" "Downloading $download_file"
  if [ $? -ne 0 ]; then
    fatal "Failed to download $1. Cannot continue. Check your network connection and DNS settings."
  else
    return 0
  fi
}

#################################################################################
#
# PID :: Check PID file, to avoid multiple instances running at the same time.
#
#################################################################################
#
    # Decide where to write our PID file. This will be in home directory.
    MYHOMEDIR=$(echo ~ 2> /dev/null)
    if [ -z "${MYHOMEDIR}" ]; then MYHOMEDIR="/tmp"; fi

    PIDFILE="${MYHOMEDIR}/pihardener.pid"

    # Check if there is already a PID file in any of the locations (incorrect termination of previous instance)
    if [ -f "${MYHOMEDIR}/pihardener.pid" ]; then
        printf "%s" "
${REDBG}Warning${NORMAL}: ${RED}PID file exists, probably another pihardener process is running.${NORMAL}
------------------------------------------------------------------------------
If you are unsure if another pihardener process is running currently, you are advised
to stop the current process and check the process list first. If you cancelled
a previous instance (by using CTRL+C), you can ignore this message.
------------------------------------------------------------------------------
"
        # Deleting any stale PID files that might exist. Note: Display function does not work yet at this point
        if [ -f "${MYHOMEDIR}/pihardener.pid" ]; then rm -f "${MYHOMEDIR}/pihardener.pid"; fi
    fi

    # Ensure symlink attack is not possible, by confirming there is no symlink of the file already
    OURPID=$(echo $$)
    if [ -L ${PIDFILE} ]; then
        echo "Found symlinked PID file (${PIDFILE}), quitting"
        exit 1
    else
        # Create new PID file writable only by owner
        echo "${OURPID}" > ${PIDFILE}
        chmod 600 ${PIDFILE}
    fi
#

################################################################################
    # Name        : RemovePIDFile()
    # Description : When defined, remove the file storing the process ID
    #
    # Parameters  : <none>
    # Returns     : <nothing>
    ################################################################################

    # Remove PID file
    RemovePIDFile() {
        # Test if PIDFILE is defined, before checking file presence
        if [ -n "${PIDFILE}" ]; then
            if [ -f "${PIDFILE}" ]; then
                rm -f "${PIDFILE}"
            fi
        fi
    }

#################################################################################
#
# Checks and MENU
#
#################################################################################

# Only root can run the script
id | grep -i "uid=0(" >/dev/null
if [ "$?" != "0" ]; then
  uname -a | grep -i CYGWIN >/dev/null
  if [ "$?" != "0" ]; then
    printf "${RED}Fatal:${NORMAL} The $PROGRAM_NAME script must be run as root.${NORMAL}\\n"
	RemovePIDFile
	exit 1
  fi
fi

# check if program was started before
if [ -f $sshd_config_max ]; then
	SECURED="MAXIMUM"
elif [ -f $sshd_config_high ]; then
	SECURED="HIGH"
elif [ -f $sshd_config_min ]; then
	SECURED="MINIMUM"
fi

# check if os is compatible (Raspbian 10)
get_distro () {
if [ "$os_type" != "raspbian" ] || [ "$os_version" != "10" ]; then
    printf "${RED}Fatal:${NORMAL} ${os_type} ${os_version} is not supported by this installer.${NORMAL}\\n"
	RemovePIDFile
    exit 1
fi
}

# welcome and version message
printf "\n	Welcome to the ${YELLOW}$PROGRAM_NAME${NORMAL}, version ${YELLOW}$PROGRAM_VERSION${NORMAL}\n	The systems currently supported by pihardener.sh are:"
echo "\n\n		${CYAN}$supported${NORMAL}\n"
printf "	If your OS/version/arch is not listed, installation ${RED}will fail${NORMAL}. More\n	details about the systems supported by the script can be found here:\n\n	https://github.com/yalefox/008-raspberry-pi-hardener\n\n"

# if we continue or stop
printf "		Continue? (y/n) "
	if ! yesno; then
	RemovePIDFile
	exit
	fi

# display the main menu
clear
echo "██████╗ ██╗      ██╗  ██╗ █████╗ ██████╗ ██████╗ "
echo "██╔══██╗██║      ██║  ██║██╔══██╗██╔══██╗██╔══██╗"
echo "██████╔╝██║█████╗███████║███████║██████╔╝██║  ██║"
echo "██╔═══╝ ██║╚════╝██╔══██║██╔══██║██╔══██╗██║  ██║"
echo "██║     ██║      ██║  ██║██║  ██║██║  ██║██████╔╝"
echo "╚═╝     ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
echo "##################################### by mclovin"
if [ $SECURED ]; then
	echo "THIS PI IS ALREADY SECURED WITH $SECURED MODE"
	echo "1. Restore defaults and reboot"
	echo "2. Exit"
else
	echo "1. Minimum security"
	echo "2. High Security"
	echo "3. Maximum Security"
	echo "4. Paranoid Security"
	echo "5. Exit"
fi

#################################################################################
#
# Hardening functions
#
#################################################################################

# sshd minimum security rules, mainly adding lines in /etc/ssh/sshd_config and /etc/ssh/moduli
sshd_min() {
	SSHD_PORT="22"
	cp --preserve /etc/ssh/sshd_config $sshd_config_min
	sed -i 's|#HostKey /etc/ssh/ssh_host_rsa_key|HostKey /etc/ssh/ssh_host_ed25519_key|g' /etc/ssh/sshd_config
	sed -i 's|#HostKey /etc/ssh/ssh_host_ecdsa_key|HostKey /etc/ssh/ssh_host_rsa_key|g' /etc/ssh/sshd_config
	sed -i 's|#HostKey /etc/ssh/ssh_host_ed25519_key|HostKey /etc/ssh/ssh_host_ecdsa_key|g' /etc/ssh/sshd_config
	echo 'KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256' >> /etc/ssh/sshd_config
	echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' >> /etc/ssh/sshd_config
	echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' >> /etc/ssh/sshd_config
	sed -i 's/#LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config
	sed -i 's/sftp-server/sftp-server -f AUTHPRIV -l INFO/g' /etc/ssh/sshd_config
	sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config
	sed -i 's/UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config
	cp --preserve /etc/ssh/moduli $moduli
	awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp && mv -f /etc/ssh/moduli.tmp /etc/ssh/moduli
	mv /etc/profile.d/sshpwd.sh $sshpwd
}

# sshd high security rules, generating public/private key and disabling password login
sshd_high() {
	apt-get -y install putty-tools
	sudo -u $USERNAME ssh-keygen -b 2048 -t rsa -f /home/$USERNAME/.ssh/id_rsa -q -N "" && mv /home/$USERNAME/.ssh/id_rsa.pub /home/$USERNAME/.ssh/authorized_keys
	puttygen /home/$USERNAME/.ssh/id_rsa -o /home/$USERNAME/.ssh/id_rsa.ppk -O private
	cp --preserve /etc/ssh/sshd_config $sshd_config_high
	sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
	passwd --lock pi
}

# sshd maximum security rules, generating random sshd port
sshd_max() {
	SSHD_PORT=$(shuf -i 20000-60000 -n 1) # sshd random port
	cp --preserve /etc/ssh/sshd_config $sshd_config_max
	sed -i "s/#Port 22/Port $SSHD_PORT/g" /etc/ssh/sshd_config
}

# sshd paranoid security rules, adding 2FA
sshd_paranoid() {
	cp --preserve /etc/ssh/sshd_config $sshd_config_paranoid
	cp --preserve /etc/pam.d/sshd $pamd_paranoid
	sed -i "s/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g" /etc/ssh/sshd_config
	sed -i 's/UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config
	echo 'AuthenticationMethods publickey,keyboard-interactive' >> /etc/ssh/sshd_config
	echo 'auth       required     pam_google_authenticator.so nullok' >> /etc/pam.d/sshd
	sed -i 's/@include common-auth/#@include common-auth/g' /etc/pam.d/sshd
}

# firewall settings for high/max mode
firewall_high() {

	# making a backup of the psad configuration file
	cp --preserve /etc/psad/psad.conf /etc/psad/psad.high
	
	# making a backup of the ufw before rules
	cp --preserve /etc/ufw/before.rules /etc/ufw/before.high
	cp --preserve /etc/ufw/before6.rules /etc/ufw/before6.high
	
	# enabling automatic IDS response
	sed -i 's/ENABLE_AUTO_IDS             N;/ENABLE_AUTO_IDS             Y;/g' /etc/psad/psad.conf
	
	# adding psad ufw rules for logging the traffic	
	sed -i "/# don't delete the 'COMMIT' line or these rules won't be processed/i\# log all traffic so psad can analyze\n-A INPUT -j LOG --log-tcp-options --log-prefix \"[IPTABLES] \"\n-A FORWARD -j LOG --log-tcp-options --log-prefix \"[IPTABLES] \"\n" /etc/ufw/before.rules
	sed -i "/# don't delete the 'COMMIT' line or these rules won't be processed/i\# log all traffic so psad can analyze\n-A INPUT -j LOG --log-tcp-options --log-prefix \"[IPTABLES] \"\n-A FORWARD -j LOG --log-tcp-options --log-prefix \"[IPTABLES] \"\n" /etc/ufw/before6.rules	

	# allow all outgoing traffic
	ufw default allow outgoing comment 'allow all outgoing traffic'
	
	# allow traffic in on port SSHD_PORT
	ufw limit in ${SSHD_PORT} comment 'allow SSH connections in'

	# allow traffic in for HTTP, HTTPS, FTP, DNS and SMTP
	ufw allow in http comment 'allow HTTP traffic in'
	ufw allow in https comment 'allow HTTPS traffic in'
	ufw allow in ftp comment 'allow FTP traffic in'
	ufw allow in dns comment 'allow DNS traffic in'
	ufw allow in smtp comment 'allow SMTP traffic in'
	
	# start the firewall and restart psad
	psad -R
	ufw --force enable
}

# firewall settings for high/max mode
firewall_paranoid() {

	# making a backup of the ufw before rules
	cp --preserve /etc/ufw/before.rules /etc/ufw/before.paranoid
	cp --preserve /etc/ufw/before6.rules /etc/ufw/before6.paranoid
	
	# deny traffic in for HTTP, HTTPS, FTP, DNS and SMTP
	ufw deny in http comment 'allow HTTP traffic in'
	ufw deny in https comment 'allow HTTPS traffic in'
	ufw deny in ftp comment 'allow FTP traffic in'
	ufw deny in dns comment 'allow DNS traffic in'
	ufw deny in smtp comment 'allow SMTP traffic in'
	
	# reload ufw rules
	ufw reload
}

# fail2ban settings for high mode
fail2ban_high() {

	# making a backup of previous sshd rule
	cp --preserve /etc/fail2ban/jail.d/defaults-debian.conf /etc/fail2ban/jail.d/defaults-debian.high
	cp --preserve /usr/lib/tmpfiles.d/fail2ban-tmpfiles.conf /usr/lib/tmpfiles.d/fail2ban-tmpfiles.high
	
	# fixing a tmp file cosmetic bug
	sed -i 's|/var/run/fail2ban|/run/fail2ban|g' /usr/lib/tmpfiles.d/fail2ban-tmpfiles.conf
	
	# adding sshd rule
	echo 'banaction = ufw
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 5' >> /etc/fail2ban/jail.d/defaults-debian.conf
	
	# reloading fail2ban rules
	fail2ban-client reload
}

# disabling bluetooth and other unused services
services_minimum() {
	systemctl $SERVICEMODE2 avahi-daemon
	systemctl $SERVICEMODE1 avahi-daemon
	systemctl $SERVICEMODE2 triggerhappy
	systemctl $SERVICEMODE1 triggerhappy
	systemctl $SERVICEMODE2 bluetooth
	systemctl $SERVICEMODE1 bluetooth
	systemctl $SERVICEMODE2 hciuart
}

# basic start settings for all menu options
min_start() {
	SERVICEMODE1="stop"
	SERVICEMODE2="disable"
	run_ok "apt-get -y update" "Updating the system"
	run_ok "apt-get -y install xkcdpass && generate_memorable_password" "Installing password generator & generating password"
	run_ok "apt-get -y install clamav" "Installing Clamav antivirus"
	run_ok "apt-get -y install unattended-upgrades apt-config-auto-update && sed -i 's/^\/\/Unattended-Upgrade::Automatic-Reboot \"false\";/Unattended-Upgrade::Automatic-Reboot \"true\";/g' /etc/apt/apt.conf.d/50unattended-upgrades && sed -i 's/^\/\/Unattended-Upgrade::Remove-Unused-Dependencies \"false\";/Unattended-Upgrade::Remove-Unused-Dependencies \"true\";/g' /etc/apt/apt.conf.d/50unattended-upgrades" "Installing automatic updates"
	run_ok "services_minimum" "Disabling bluetooth and unused services"
}

# high start settings for high/maximum/paranoid options
high_start() {
	run_ok "apt-get -y install ufw fail2ban psad rkhunter chkrootkit libpam-google-authenticator" "Installing Security Services"
	run_ok "add_sudo_user && echo '$USERNAME:$PASSWORD' | chpasswd" "Adding user $USERNAME with random password"
	run_ok "fail2ban_high" "Configuring fail2ban"
}

# Restart SSH for all
min_end() {
	run_ok "service sshd restart" "Restarting OpenSSH"
}

# high end settings for high/maximum/security
high_end() {
	printf "\n${YELLOW}This is your freshly generated SSH PRIVATE KEY for putty, you have to save it${NORMAL}\n\n"
	echo "			${CYAN}SSH PRIVATE KEY : ${NORMAL}\n" && cat "/home/$USERNAME/.ssh/id_rsa.ppk"
	printf "\n	${RED}You WILL NOT be able to log in if you do not save it !!!${NORMAL}\n\n"
}

# Show NEW SSH port
max_end() {
	printf "\n${YELLOW}This is the new SSH PORT for putty, use it to connect to your server${NORMAL}\n\n"
	echo "			${CYAN}SSH NEW PORT : ${SSHD_PORT}${NORMAL}"
	printf "\n	${RED}You WILL NOT be able to log in if you do not save it !!!${NORMAL}\n\n"
}

#################################################################################
#
# Hardening START
#
#################################################################################

# Start the hardening for the minimum settings
install_min() {
	USERNAME="pi"
	min_start
	run_ok "sshd_min" "Securing OpenSSH"
	run_ok "echo '$USERNAME:$PASSWORD' | chpasswd" "Changing pi user password"
	printf "\n	${YELLOW}This is your NEW user password, copy it or write it down${NORMAL}\n\n"
	echo "		${CYAN}USER : ${CYAN}$USERNAME${NORMAL}"
	echo "		${CYAN}PASSWORD : ${CYAN}$PASSWORD${NORMAL}\n"
	printf "	${RED}You WILL NOT be able to log in to ssh if you do not write/remember it !!!${NORMAL}\n\n"
	min_end # Restart SSHD
	printf "\n		${CYAN}This system has now been secured to MINIMUM level\n${NORMAL}"
}

# Start the hardening for the high settings
install_high() {
	read -p "Enter new username to create : " USERNAME
	min_start # Minimum settings hardening
	high_start # High settings hardening
	run_ok "sshd_min && sshd_high" "Securing OpenSSH"
	run_ok "firewall_high" "Configuring IDS/IPS and starting the firewall"
	run_ok "cp --preserve /etc/sudoers.d/010_pi-nopasswd /etc/sudoers.d/010_pi-nopasswd.high && sed -i 's/pi/$USERNAME/g' /etc/sudoers.d/010_pi-nopasswd" "Updating sudoers"
	high_end # Show private KEY
	min_end # Restart SSHD
	printf "\n		${CYAN}This system has now been secured to HIGH level\n${NORMAL}"
}

# Start the hardening for the maximum settings
install_maximum() {
	read -p "Enter new username to create : " USERNAME
	min_start # Minimum settings hardening
	high_start # High settings hardening
	run_ok "sshd_min && sshd_high && sshd_max" "Securing OpenSSH"
	run_ok "firewall_high" "Configuring IDS/IPS and starting the firewall"
	run_ok "mv /etc/sudoers.d/010_pi-nopasswd /etc/sudoers.d/010_pi-nopasswd.max" "Updating sudoers" # Removing sudoers file
	run_ok "echo '$USERNAME:$PASSWORD' | chpasswd" "Changing user password"
	printf "\n	${YELLOW}This is your NEW user password, copy it or write it down${NORMAL}\n\n"
	echo "		${CYAN}USER : ${CYAN}$USERNAME${NORMAL}"
	echo "		${CYAN}PASSWORD : ${CYAN}$PASSWORD${NORMAL}\n"
	printf "	${RED}You WILL NOT be able to use SUDO if you do not write/remember it !!!${NORMAL}\n\n"
	high_end # Show private KEY
	max_end # Show new SSH port
	min_end # Restart SSHD
	printf "\n		${CYAN}This system has now been secured to MAXIMUM level\n${NORMAL}"
}

# Start the hardening for the paranoid settings (IN PROGRESS)
install_paranoid() {
	read -p "Enter new username to create : " USERNAME
	min_start # Minimum settings hardening
	high_start # High settings hardening
	run_ok "sshd_min && sshd_high && sshd_max && sshd_paranoid" "Securing OpenSSH"
	run_ok "firewall_high && firewall_paranoid" "Configuring IDS/IPS and starting the firewall"
	run_ok "mv /etc/sudoers.d/010_pi-nopasswd /etc/sudoers.d/010_pi-nopasswd.max" "Updating sudoers" # Removing sudoers file
	run_ok "echo '$USERNAME:$PASSWORD' | chpasswd" "Changing user password"
	run_ok "echo '1-1' | tee /sys/bus/usb/drivers/usb/unbind" "Disabling power on USB ports"
	printf "\n	${YELLOW}This is your NEW user password, copy it or write it down${NORMAL}\n\n"
	echo "		${CYAN}USER : ${CYAN}$USERNAME${NORMAL}"
	echo "		${CYAN}PASSWORD : ${CYAN}$PASSWORD${NORMAL}\n"
	printf "	${RED}You WILL NOT be able to use SUDO if you do not write/remember it !!!${NORMAL}\n\n"
	high_end # Show private KEY
	sudo -u $USERNAME google-authenticator -ftdu -w 3 -Q UTF8
	max_end # Show new SSH port
	min_end # Restart SSHD
	printf "\n		${CYAN}This system has now been secured to PARANOID level\n${NORMAL}"
}

# Restoring defaults settings before hardening
restore_defaults() {
	SERVICEMODE1="start"
	SERVICEMODE2="enable"
	run_ok "apt-get -y autoremove --purge xkcdpass" "Removing password generator"
	run_ok "apt-get -y autoremove --purge clamav" "Removing Clamav antivirus"
	run_ok "apt-get -y autoremove --purge unattended-upgrades apt-config-auto-update" "Removing automatic updates"
	run_ok "services_minimum" "Enabling bluetooth and other services"
	run_ok "apt-get -y autoremove --purge ufw fail2ban psad rkhunter chkrootkit" "Removing Security Services"
	run_ok "apt-get -y autoremove --purge putty-tools" "Removing putty tools"
	run_ok "passwd --unlock pi" "Unlocking user pi"
	run_ok "echo 'pi:raspberry' | chpasswd" "Setting pi user password to default"
	run_ok "mv $sshd_config_min /etc/ssh/sshd_config && mv $sshpwd /etc/profile.d/sshpwd.sh" "Restoring sshd configuration file"
	run_ok "mv $moduli /etc/ssh/moduli" "Restoring moduli file"
	run_ok "mv $pamd_paranoid /etc/pam.d/sshd" "Restoring pamd file"
	if [ -f $sudoers_high ]; then
		run_ok "mv /etc/sudoers.d/010_pi-nopasswd.high /etc/sudoers.d/010_pi-nopasswd" "Restoring sudoers file"
	fi
	run_ok "rm -f $sshd_config_high $sshd_config_max $sudoers_high $sudoers_max $" "Cleaning backup files"
	min_end # Restart SSHD
	printf "\n		${CYAN}This system security has now been restored to defaults, the actual user was NOT removed\n${NORMAL}"
	printf "\n		${CYAN}Please remember to log in to ssh port 22 with user pi and password raspberry\n${NORMAL}"
}

# Read input from the keyboard and take an action
if [ $SECURED ]; then
	read -p "Enter choice [1 - 2] " choice
	case $choice in
		1) restore_defaults ;;
		2) RemovePIDFile && exit 0;;
		*) RemovePIDFile && echo "${RED}Fatal:${NORMAL} Error...." && exit 1
	esac
else
	read -p "Enter choice [1 - 5] " choice
	case $choice in
	1) install_min ;;
	2) install_high ;;
	3) install_maximum ;;
	4) install_paranoid ;;
	5) RemovePIDFile && exit 0;;
	*) RemovePIDFile && echo "${RED}Fatal:${NORMAL} Error...." && exit 1
esac
fi

#################################################################################
#
# Hardening END
#
#################################################################################

# Reap any clingy processes (like spinner forks)
# get the parent pids (as those are the problem)
allpids="$(ps -o pid= --ppid $$) $allpids"
for pid in $allpids; do
  kill "$pid" 1>/dev/null 2>&1
done

# Make sure the cursor is back (if spinners misbehaved)
tput cnorm

# Remove the PID file
RemovePIDFile

# ask for upgrades and reboot
printf "\n	${RED}Install system upgrades and reboot! Continue (y/n)\n${NORMAL}"
if yesno; then
	apt-get -y upgrade && apt-get -y autoremove && apt-get -y clean all && shutdown -r now
fi
exit
