#!/bin/bash
#     ____     ######################################
#    /___/`    # easytools.sh  
#    (O,O)     # Utilité: ce script sert à configurer les serveurs
#   /(   )\    # Usage: easytools.sh -option1 -option2 ... (Voir l'aide -h)
# --==M=M==--  # Auteur: Johny BIGOUD <j.bigoud@flowerpower.org>
#     Easy     # Mise à jour le: 00/00/0000
# F O R M E R  ######################################

nomduscript="EasyTools"

############################################################################
####################   Déclaration des variables   #########################
############################################################################

maron='\e[0;3m'
noir='\e[0;30m'
gris='\e[1;30m'
rougefonce='\e[0;31m'
rose='\e[1;31m'
vertfonce='\e[0;32m'
vertclair='\e[1;32m'
orange='\e[0;33m'
jaune='\e[1;33m'
bleufonce='\e[0;34m'
bleuclair='\e[1;34m'
violetfonce='\e[0;35m'
violetclair='\e[1;35m'
cyanfonce='\e[0;36m'
cyanclair='\e[1;36m'
grisclair='\e[0;37m'
blanc='\e[1;37m'
neutre='\e[0;m'

sudo apt-get -y install figlet > /dev/null

# Initialisation des tableaux logo et nom du script
declare -a nomScripMultiligne
while IFS= read -r ligne; do
    nomScripMultiligne+=("$ligne")
done <<< `figlet -k $nomduscript`

declare -a logoEasy
logoEasy=(
    " ${bleuclair}    ____   ${vertfonce}"
    " ${bleuclair}   /___/${rougefonce}\`  ${vertfonce}"
    " ${maron}   (${jaune}O${maron},${jaune}O${maron})${vertfonce}   "
    " ${maron}  /(   )\\ ${vertfonce} "
    " ${grisclair}--==${noir}M${grisclair}=${noir}M${grisclair}==--${vertfonce}"
    " ${vertclair}    Easy   ${vertfonce}"
    " ${vertfonce}F O R M E R${neutre}"
)

# Déclaration des tableaux associatifs pour stocker les informations
declare -A helpDescriptions
declare -A categoryMenus
declare -A nameMenus
declare -A commutatorLetters
declare -A commutatorWords
declare -A commutatorLettersErrors
declare -A commutatorWordsErrors

############################################################################
####################   Déclaration des fonctions   #########################
############################################################################

# afficher le nom du script
printLogo(){
	for ligne in "${logoEasy[@]}"; do
		echo -e "$ligne"
	done
}

# afficher le nom du script
printScriptName(){
	for element in "${nomScripMultiligne[@]}"; do
		echo -e "${vertfonce} $element ${neutre}"
	done
}

# afficher le nom du script centré
printScriptNameCenter(){
	echo -e "${vertfonce}`figlet -ck $nomduscript`${neutre}"
}

# afficher le logo et le nom du script
printLogoAndNameScript(){
	for i in "${!logoEasy[@]}"; do
		echo -e "${logoEasy[$i]}" "${nomScripMultiligne[$i]}"
	done
}

# Fonction pour parser le script et extraire les informations
parser_fonctions() {
    local current_function=""
    while IFS= read -r line; do
        # Check for function names
        if [[ $line =~ ^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\) ]]; then
            current_function="${BASH_REMATCH[1]}"
        fi

        # Check for meta information if current_function is set
        if [[ -n $current_function ]]; then
            if [[ $line =~ ^\#helpDescription=\"(.*)\"$ ]]; then
                helpDescriptions["$current_function"]="${BASH_REMATCH[1]}"
            elif [[ $line =~ ^\#categoryMenu=\"(.*)\"$ ]]; then
                categoryMenus["$current_function"]="${BASH_REMATCH[1]}"
            elif [[ $line =~ ^\#nameMenu=\"(.*)\"$ ]]; then
                nameMenus["$current_function"]="${BASH_REMATCH[1]}"
            elif [[ $line =~ ^\#commutatorLetter=\"(.*)\"$ ]]; then
                commutatorLetters["$current_function"]="${BASH_REMATCH[1]}"
            elif [[ $line =~ ^\#commutatorWord=\"(.*)\"$ ]]; then
                commutatorWords["$current_function"]="${BASH_REMATCH[1]}"
            fi
        fi
    done < "$1"
}

printInfoFunction(){
	# Afficher les informations extraites
    echo ""
    echo -e "${vertfonce}     Manuel pour les développeurs${neutre}"
    echo ""
	for func in "${!helpDescriptions[@]}"; do
		echo "Fonction: $func"
		echo "  helpDescription: ${helpDescriptions[$func]}"
		echo "  categoryMenu: ${categoryMenus[$func]}"
		echo "  nameMenu: ${nameMenus[$func]}"
		echo "  commutatorLetter: ${commutatorLetters[$func]}"
		echo "  commutatorWord: ${commutatorWords[$func]}"
		echo ""
	done
}

printHelp() {
	printLogoAndNameScript
    echo ""
    echo -e "${vertfonce}     Manuel d'utilisation${neutre}"
    echo ""
    echo "Tappez q pour quitter l'aide."
    echo ""
	
	for func in "${!helpDescriptions[@]}"; do
		if [[ -n ${commutatorLetters[$func]} && -n ${commutatorWords[$func]} ]];then
			echo -e "-${commutatorLetters[$func]} ou --${commutatorWords[$func]} (${categoryMenus[$func]})"
			echo "  ${helpDescriptions[$func]}"
			echo ""
		elif [[ -n ${commutatorLetters[$func]} ]];then
			echo -e "-${commutatorLetters[$func]} (${categoryMenus[$func]})"
			echo "  ${helpDescriptions[$func]}"
			echo ""
		elif [[ -n ${commutatorWords[$func]} ]];then
			echo -e "--${commutatorWords[$func]} (${categoryMenus[$func]})"
			echo "  ${helpDescriptions[$func]}"
			echo ""
		fi
	done
	printInfoFunction
    echo ""
    echo "Tappez q pour quitter l'aide."
    echo ""
}

printHelpMore() {
	helpContent=$(printHelp)
	echo "$helpContent" | more
}

printMainPage(){
	#clear
	printLogoAndNameScript
	for ((i = 0; i < ${#commutatorLettersErrors[@]}; i+=1)); do
		echo -e "${rougefonce}  Attention le commutateur -${commutatorLettersErrors[$i]} est en doublon${neutre}"
	done
	for ((i = 0; i < ${#commutatorWordsErrors[@]}; i+=1)); do
		echo -e "${rougefonce}  Attention le commutateur --${commutatorWordsErrors[$i]} est en doublon${neutre}"
	done
	# Appel de la fonction pour afficher le menu
	printMainMenu
}

# Fonction pour afficher le menu principal et gérer les choix
printMainMenu() {

	# Créer un tableau uniquement pour les options de menu
	menu_options=()
	for ((i = 0; i < ${#optionsMainMenu[@]}; i+=2)); do
		menu_options+=("${optionsMainMenu[$i]}")
	done

    echo ""
    echo -e "${vertfonce}     Menu principal${neutre}"
    echo ""
    PS3='  Veuillez choisir une option: '
    select opt in "${menu_options[@]}"; do
        for ((i = 0; i < ${#menu_options[@]}; i++)); do
            if [[ "$opt" == "${menu_options[$i]}" ]]; then
                if [[ "${optionsMainMenu[$((i * 2 + 1))]}" == "quit" ]]; then
					exit 1
                elif [[ "${optionsMainMenu[$((i * 2 + 1))]}" == "help" ]]; then
					printHelpMore
                    printMainPage
                else
                    printSubMenu  "${optionsMainMenu[$((i * 2 + 1))]}" "${optionsMainMenu[$((i * 2))]}"
					printMainPage
                fi
            fi
        done
        if [[ "$opt" == "" ]]; then
            echo -e "${rougefonce}     Option invalide $REPLY${neutre}"
        fi
    done
}

printSubMenu() {
	#clear
	printLogoAndNameScript
    echo ""
	menuTitle="$2"
	first=${menuTitle:0:1}
	rest=${menuTitle:1}
	menuTitleLower=${first,,}$rest
    echo -e "${vertfonce}     Menu $menuTitleLower${neutre}"
    echo ""
	
	sub_menu_text=()
	sub_menu_function=()
	for func in "${!helpDescriptions[@]}"; do
		if [ -n "$1" ] && [ -n "${categoryMenus[$func]}" ] && [ "${categoryMenus[$func]}" == "$1" ]; then
			sub_menu_text+=("${nameMenus[$func]}")
			sub_menu_function+=("$func")
		fi
	done
	sub_menu_text+=("Manuel d'utilisation")
	sub_menu_function+=("help")
	sub_menu_text+=("Retour au menu principal")
	sub_menu_function+=("quit")
	PS3='  Veuillez choisir une option: '
    select optMenu in "${sub_menu_text[@]}"; do
        for ((i = 0; i < ${#sub_menu_text[@]}; i++)); do
            if [[ "$optMenu" == "${sub_menu_text[$i]}" ]]; then
                if [[ "${sub_menu_function[$i]}" == "quit" ]]; then
					printMainPage
                elif [[ "${sub_menu_function[$i]}" == "help" ]]; then
					printHelpMore
                    printSubMenu  "$1" "$2"
                else
                    ${sub_menu_function[$i]}
                    printSubMenu  "$1" "$2"
                fi
            fi
        done
        if [[ "$optMenu" == "" ]]; then
            echo -e "${rougefonce}     Option invalide $REPLY${neutre}"
        fi
    done

}

############################################################################
# Les informations suivantes doivent toujours être présentes dans les fonctions
# pour automatiser l'aide, le lancement par attribut et l'insertion dans les menus :
############################################################################
#helpDescription=""
#categoryMenu=""
#nameMenu=""
#commutatorLetter=""
#commutatorWord=""
############################################################################
# Voici les catégories de menu que vous pouvez mettre :
#    "admin", "parameter", "authentication", "mail", "security", "agent" et "apps"
############################################################################
# pour en rajouter utiliser la variable suivante:
optionsMainMenu=(
    "Administration" "admin"
    "Parametrage" "parameter"
    "Authentification" "authentication"
    "Messagerie" "mail"
    "Sécurité" "security"
    "Supervision" "agent"
    "Installation" "apps"
    "Manuel d'utilisation" "help"
    "Quitter" "quit"
)
############################################################################
tools_functions=$(cat << 'EOF'
############################################################################
####################   Déclaration des fonctions   #########################
####################     relatives aux outils      #########################
####################     présents dans le menu     #########################
############################################################################

generate_and_install_ssh_key(){
#helpDescription="Cette fonction génère une paire de clés SSH et installe la clé publique sur un serveur distant."
#categoryMenu="authentication"
#nameMenu="Générer et installer une clé SSH"
#commutatorLetter="k"
#commutatorWord="generate_install_ssh_key"

    # Chemin du fichier de clé par défaut
    KEY_FILE="$HOME/.ssh/id_rsa"
    
    # Génération de la paire de clés SSH
    echo "Génération d'une paire de clés SSH..."
    if [ ! -f "$KEY_FILE" ]; then
        ssh-keygen -t rsa -b 4096 -f "$KEY_FILE" -N ""
        echo "Paire de clés SSH générée avec succès."
    else
        echo "Une paire de clés SSH existe déjà à l'emplacement $KEY_FILE."
    fi
    
    # Demander l'adresse de l'utilisateur distant et le mot de passe pour l'installation de la clé publique
    read -p "Entrez l'adresse de l'utilisateur distant (ex. user@remote_host): " REMOTE_USER_HOST
    read -sp "Entrez le mot de passe de l'utilisateur distant: " REMOTE_PASSWORD
    echo
    
    # Installer la clé publique sur le serveur distant
    echo "Installation de la clé publique sur le serveur distant..."
    sshpass -p "$REMOTE_PASSWORD" ssh-copy-id -i "$KEY_FILE.pub" "$REMOTE_USER_HOST"
    
    if [ $? -eq 0 ]; then
        echo "Clé publique installée avec succès sur $REMOTE_USER_HOST."
    else
        echo "Échec de l'installation de la clé publique."
    fi
}

mise_a_jour_liste_packages() {
#helpDescription="Met à jour la liste des packages"
#categoryMenu="admin"
#nameMenu="Mise à jour de la liste des packages"
#commutatorLetter="u"
#commutatorWord="update-packages"
    echo -e "Mise à jour de la liste des packages..."
    apt-get -y update
}

mise_a_jour_packages_existants() {
#helpDescription="Met à jour les packages existants"
#categoryMenu="admin"
#nameMenu="Mise à jour des packages existants"
#commutatorLetter="i"
#commutatorWord="upgrade-packages"
    echo -e "Mise à jour des packages existants..."
    NEEDRESTART_MODE=a apt-get upgrade -y
}

installation_firewall_iptable() {
#helpDescription="Installe le firewall Iptables"
#categoryMenu="admin"
#nameMenu="Installation du firewall Iptables"
#commutatorLetter="f"
#commutatorWord="install-iptables"
    echo -e "Installation du firewall IPtable..."
    apt-get install iptables -y
}

protection_flood_iptable() {
#helpDescription="Activer une protection contre le flood avec Iptables"
#categoryMenu="admin"
#nameMenu="Protection contre le flood avec Iptables"
#commutatorLetter="p"
#commutatorWord="protect-flood"
    echo -e "Installation de la protection contre le flood avec IPtable..."
    iptables -A FORWARD -p tcp --syn -m limit --limit 1/second -j ACCEPT
    iptables -A FORWARD -p udp -m limit --limit 1/second -j ACCEPT
    iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
}

protection_scan_iptable() {
#helpDescription="Protection contre les scans de port avec Iptables"
#categoryMenu="admin"
#nameMenu="Protection contre les scans de port avec Iptables"
#commutatorLetter="s"
#commutatorWord="protect-scan"
    echo -e "Installation d'une protection contre les scan de port avec IPtable..."
    iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
}

installation_portsentry() {
#helpDescription="Installe Portsentry pour détecter les scans de ports"
#categoryMenu="admin"
#nameMenu="Installation de Portsentry"
#commutatorLetter="t"
#commutatorWord="install-portsentry"
    echo -e "Installation d'une protection contre les scan de port avec Portsentry..."
    DEBIAN_FRONTEND=noninteractive apt-get install portsentry -y
    # Ajouter ici la configuration spécifique de Portsentry
}

installation_fail2ban() {
#helpDescription="Installe Fail2ban pour protéger contre les attaques par force brute"
#categoryMenu="admin"
#nameMenu="Installation de Fail2ban"
#commutatorLetter="b"
#commutatorWord="install-fail2ban"
    echo -e "Installation d'une protection contre le brute-force avec Fail2ban..."
    local futursshport=$(demander_information "Quel port TCP souhaitez-vous pour le service SSH ? ")
    local maxretryloginssh=$(demander_information "Combien voulez-vous autoriser de tentatives de connexion échouées ? ")
    local bantime=$(demander_information "Combien de temps voulez-vous bannir l'attaquant (en secondes) ? ")
    DEBIAN_FRONTEND=noninteractive apt-get install fail2ban -y
    # Configuration spécifique de Fail2ban
    sed -i -e "s/^#Port.*/Port = $futursshport/g" /etc/ssh/sshd_config
    sed -i -e "s/^maxretry.*/maxretry = $maxretryloginssh/g" /etc/fail2ban/jail.conf 
    sed -i -e "s/^bantime.*/bantime = $bantime/g" /etc/fail2ban/jail.conf 
}

installation_rkhunter() {
#helpDescription="Installe Rkhunter pour détecter les rootkits"
#categoryMenu="admin"
#nameMenu="Installation de Rkhunter"
#commutatorLetter="r"
#commutatorWord="install-rkhunter"
    echo -e "Installation d'une protection contre les rootkits avec Rkhunter..."
    local mailrkhunter=$(demander_information "Indiquez le mail d'alerte pour Rkhunter : ")
    DEBIAN_FRONTEND=noninteractive apt-get install rkhunter -y
    sed -i "s|REPORT_EMAIL.*=.*\"\"|REPORT_EMAIL=\"$mailrkhunter\"|g" /etc/default/rkhunter
    sed -i "s|CRON_DAILY_RUN.*=.*\"\"|CRON_DAILY_RUN=\"yes\"|g" /etc/default/rkhunter
}

installation_logwatch() {
#helpDescription="Installe Logwatch pour analyser les logs"
#categoryMenu="admin"
#nameMenu="Installation de Logwatch"
#commutatorLetter="l"
#commutatorWord="install-logwatch"
    echo -e "Installation de Logwatch pour l'analyse de logs..."
    local maillogwatch=$(demander_information "Indiquez le mail d'alerte pour Logwatch : ")
    DEBIAN_FRONTEND=noninteractive apt-get install logwatch -y
    sed -i "s|MailTo.*=.*root|MailTo=\"$maillogwatch\"|g" /usr/share/logwatch/default.conf/logwatch.conf
}

redemarrer_services() {
#helpDescription="Redémarre les services pour appliquer les changements"
#categoryMenu="admin"
#nameMenu="Redémarrage des services"
#commutatorLetter="x"
#commutatorWord="restart-services"
    echo -e "Redémarrage des services..."
    systemctl restart dbus.service networkd-dispatcher.service systemd-logind.service unattended-upgrades.service user@1000.service
}

installation_docker() {
#helpDescription="Installe Docker pour la gestion des conteneurs"
#categoryMenu="admin"
#nameMenu="Installation de Docker"
#commutatorLetter="d"
#commutatorWord="install-docker"
    echo -e "Installation de Docker..."
    apt-get update
    apt-get install -y docker.io
    systemctl start docker
    systemctl enable docker
}

installation_htop() {
#helpDescription="Installe htop pour la surveillance des ressources système"
#categoryMenu="admin"
#nameMenu="Installation de htop"
#commutatorLetter="h"
#commutatorWord="install-htop"
    echo -e "Installation de htop..."
    apt-get install -y htop
}

installation_vim() {
#helpDescription="Installe vim pour l'édition de texte"
#categoryMenu="admin"
#nameMenu="Installation de vim"
#commutatorLetter="v"
#commutatorWord="install-vim"
    echo -e "Installation de vim..."
    apt-get install -y vim
}

parametrage_ntp() {
#helpDescription="Paramètre le service NTP pour synchroniser l'heure du système"
#categoryMenu="parameter"
#nameMenu="Paramétrage du service NTP"
#commutatorLetter="n"
#commutatorWord="param-ntp"
    echo -e "Paramétrage du service NTP..."
    apt-get install -y ntp
    systemctl start ntp
    systemctl enable ntp
}

parametrage_locale() {
#helpDescription="Paramètre les locales du système"
#categoryMenu="parameter"
#nameMenu="Paramétrage des locales"
#commutatorLetter="l"
#commutatorWord="param-locale"
    echo -e "Paramétrage des locales..."
    dpkg-reconfigure locales
}

parametrage_timezone() {
#helpDescription="Paramètre le fuseau horaire du système"
#categoryMenu="parameter"
#nameMenu="Paramétrage du fuseau horaire"
#commutatorLetter="t"
#commutatorWord="param-timezone"
    echo -e "Paramétrage du fuseau horaire..."
    dpkg-reconfigure tzdata
}

parametrage_hostname() {
#helpDescription="Paramètre le nom d'hôte du système"
#categoryMenu="parameter"
#nameMenu="Paramétrage du nom d'hôte"
#commutatorLetter="h"
#commutatorWord="param-hostname"
    echo -e "Paramétrage du nom d'hôte..."
    local new_hostname=$(demander_information "Indiquez le nouveau nom d'hôte : ")
    hostnamectl set-hostname $new_hostname
    echo "$new_hostname" > /etc/hostname
    echo "127.0.1.1 $new_hostname" >> /etc/hosts
}

parametrage_hosts() {
#helpDescription="Paramètre le fichier hosts du système"
#categoryMenu="parameter"
#nameMenu="Paramétrage du fichier hosts"
#commutatorLetter="s"
#commutatorWord="param-hosts"
    echo -e "Paramétrage du fichier hosts..."
    nano /etc/hosts
}

installation_pam() {
#helpDescription="Installe et configure PAM pour la gestion des accès"
#categoryMenu="authentication"
#nameMenu="Installation de PAM"
#commutatorLetter="p"
#commutatorWord="install-pam"
    echo -e "Installation de PAM..."
    apt-get install -y libpam0g-dev
}

installation_mfa() {
#helpDescription="Installe et configure une solution MFA"
#categoryMenu="authentication"
#nameMenu="Installation de MFA"
#commutatorLetter="m"
#commutatorWord="install-mfa"
    echo -e "Installation de MFA..."
    apt-get install -y libpam-google-authenticator
    echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
}

installation_sso() {
#helpDescription="Installe et configure une solution SSO"
#categoryMenu="authentication"
#nameMenu="Installation de SSO"
#commutatorLetter="s"
#commutatorWord="install-sso"
    echo -e "Installation de SSO..."
    # Commandes pour installer SSO
}

installation_ldap() {
#helpDescription="Installe et configure un serveur LDAP"
#categoryMenu="authentication"
#nameMenu="Installation de LDAP"
#commutatorLetter="l"
#commutatorWord="install-ldap"
    echo -e "Installation de LDAP..."
    apt-get install -y slapd ldap-utils
    dpkg-reconfigure slapd
}

installation_kerberos() {
#helpDescription="Installe et configure un serveur Kerberos"
#categoryMenu="authentication"
#nameMenu="Installation de Kerberos"
#commutatorLetter="k"
#commutatorWord="install-kerberos"
    echo -e "Installation de Kerberos..."
    apt-get install -y krb5-kdc krb5-admin-server
    dpkg-reconfigure krb5-kdc
}

installation_postfix() {
#helpDescription="Installe et configure Postfix pour la gestion des mails"
#categoryMenu="mail"
#nameMenu="Installation de Postfix"
#commutatorLetter="p"
#commutatorWord="install-postfix"
    echo -e "Installation de Postfix..."
    apt-get install -y postfix
    dpkg-reconfigure postfix
}

installation_dovecot() {
#helpDescription="Installe et configure Dovecot pour la gestion des mails"
#categoryMenu="mail"
#nameMenu="Installation de Dovecot"
#commutatorLetter="d"
#commutatorWord="install-dovecot"
    echo -e "Installation de Dovecot..."
    apt-get install -y dovecot-imapd dovecot-pop3d
    systemctl start dovecot
    systemctl enable dovecot
}

installation_spamassassin() {
#helpDescription="Installe et configure SpamAssassin pour filtrer les spams"
#categoryMenu="mail"
#nameMenu="Installation de SpamAssassin"
#commutatorLetter="s"
#commutatorWord="install-spamassassin"
    echo -e "Installation de SpamAssassin..."
    apt-get install -y spamassassin
    systemctl start spamassassin
    systemctl enable spamassassin
}

installation_roundcube() {
#helpDescription="Installe et configure Roundcube pour la gestion des mails via webmail"
#categoryMenu="mail"
#nameMenu="Installation de Roundcube"
#commutatorLetter="r"
#commutatorWord="install-roundcube"
    echo -e "Installation de Roundcube..."
    apt-get install -y roundcube
}

installation_clamav() {
#helpDescription="Installe et configure ClamAV pour la protection antivirus"
#categoryMenu="security"
#nameMenu="Installation de ClamAV"
#commutatorLetter="c"
#commutatorWord="install-clamav"
    echo -e "Installation de ClamAV..."
    apt-get install -y clamav clamav-daemon
    systemctl start clamav-daemon
    systemctl enable clamav-daemon
}

installation_aide() {
#helpDescription="Installe et configure AIDE pour la détection d'intrusion"
#categoryMenu="security"
#nameMenu="Installation de AIDE"
#commutatorLetter="a"
#commutatorWord="install-aide"
    echo -e "Installation de AIDE..."
    apt-get install -y aide
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
}

installation_tripwire() {
#helpDescription="Installe et configure Tripwire pour la détection d'intrusion"
#categoryMenu="security"
#nameMenu="Installation de Tripwire"
#commutatorLetter="t"
#commutatorWord="install-tripwire"
    echo -e "Installation de Tripwire..."
    apt-get install -y tripwire
    dpkg-reconfigure tripwire
}

installation_nagios() {
#helpDescription="Installe et configure Nagios pour la supervision"
#categoryMenu="agent"
#nameMenu="Installation de Nagios"
#commutatorLetter="n"
#commutatorWord="install-nagios"
    echo -e "Installation de Nagios..."
    apt-get install -y nagios4 nagios-plugins-contrib nagios-nrpe-plugin
    systemctl start nagios4
    systemctl enable nagios4
}

installation_zabbix_agent() {
#helpDescription="Installe et configure l'agent Zabbix pour la supervision"
#categoryMenu="agent"
#nameMenu="Installation de l'agent Zabbix"
#commutatorLetter="z"
#commutatorWord="install-zabbix-agent"
    echo -e "Installation de l'agent Zabbix..."
    apt-get install -y zabbix-agent
    systemctl start zabbix-agent
    systemctl enable zabbix-agent
}

installation_prometheus() {
#helpDescription="Installe et configure Prometheus pour la supervision"
#categoryMenu="agent"
#nameMenu="Installation de Prometheus"
#commutatorLetter="p"
#commutatorWord="install-prometheus"
    echo -e "Installation de Prometheus..."
    apt-get install -y prometheus
    systemctl start prometheus
    systemctl enable prometheus
}

installation_grafana() {
#helpDescription="Installe et configure Grafana pour la visualisation des données de supervision"
#categoryMenu="agent"
#nameMenu="Installation de Grafana"
#commutatorLetter="g"
#commutatorWord="install-grafana"
    echo -e "Installation de Grafana..."
    apt-get install -y grafana
    systemctl start grafana-server
    systemctl enable grafana-server
}

installation_ansible() {
#helpDescription="Installe et configure Ansible pour la gestion des configurations"
#categoryMenu="apps"
#nameMenu="Installation d'Ansible"
#commutatorLetter="a"
#commutatorWord="install-ansible"
    echo -e "Installation d'Ansible..."
    apt-get install -y ansible
}

installation_wazuh() {
#helpDescription="Installe et configure Wazuh pour la sécurité et la supervision"
#categoryMenu="apps"
#nameMenu="Installation de Wazuh"
#commutatorLetter="w"
#commutatorWord="install-wazuh"
    echo -e "Installation de Wazuh..."
    # Commandes pour installer Wazuh
}

installation_glpi() {
#helpDescription="Installe et configure GLPI pour la gestion des services IT"
#categoryMenu="apps"
#nameMenu="Installation de GLPI"
#commutatorLetter="g"
#commutatorWord="install-glpi"
    echo -e "Installation de GLPI..."
    # Commandes pour installer GLPI
}

installation_zabbix() {
#helpDescription="Installe et configure Zabbix pour la supervision"
#categoryMenu="apps"
#nameMenu="Installation de Zabbix"
#commutatorLetter="z"
#commutatorWord="install-zabbix"
    echo -e "Installation de Zabbix..."
    # Commandes pour installer Zabbix
}

installation_jenkins() {
#helpDescription="Installe et configure Jenkins pour l'intégration continue"
#categoryMenu="apps"
#nameMenu="Installation de Jenkins"
#commutatorLetter="j"
#commutatorWord="install-jenkins"
    echo -e "Installation de Jenkins..."
    apt-get install -y jenkins
    systemctl start jenkins
    systemctl enable jenkins
}

installation_gitlab() {
#helpDescription="Installe et configure GitLab pour la gestion de code source"
#categoryMenu="apps"
#nameMenu="Installation de GitLab"
#commutatorLetter="g"
#commutatorWord="install-gitlab"
    echo -e "Installation de GitLab..."
    apt-get install -y gitlab
    # Commandes pour configurer GitLab
}

############################################################################
####################      Appel des fonctions      #########################
############################################################################
EOF
)

# Chargement des tools (foncions personnalisées)
eval "$tools_functions"

generate_and_install_ssh_key

# Appel de la fonction pour parser les fonctions
parser_fonctions "$tools_functions"

# verifif de la presence des attributs
for attribut in $*
do
	if [ $attribut = "--help" ] || [[ $attribut =~ ^\-[^-]*h ]];then
		printHelpMore
        printMainPage
	fi
	for func in "${!helpDescriptions[@]}"; do
		if [ $attribut = "--${commutatorWords[$func]}" ] || ( [[ -n ${commutatorLetters[$func]} ]]  && [[ $attribut =~ ^\-[^-]*${commutatorLetters[$func]} ]] );then
			$func
			echo $func
			sleep 2
		fi
	done
done

# Affichage de la page principale
printMainPage
