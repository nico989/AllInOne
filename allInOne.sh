#!/bin/bash

# Fail on unset var usage
set -o nounset
# Prevents errors in a pipeline from being masked
set -o pipefail

TARGET=""
KEY=""

function installDependencies() {
	echo "[+] Update system and check dependencies..."
	sudo apt update > /dev/null 2>&1

	dpkg -s whois > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install whois..."
		sudo apt install whois -y > /dev/null 2>&1
	fi

	dpkg -s assetfinder > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install assetfinder..."
		sudo apt install assetfinder -y > /dev/null 2>&1
	fi

	dpkg -s httprobe > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install httprobe..."
		sudo apt install httprobe -y > /dev/null 2>&1
	fi

	dpkg -s whatweb > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install whatweb..."
		sudo apt install whatweb -y > /dev/null 2>&1
	fi

	dpkg -s nmap > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install nmap..."
		sudo apt install nmap -y > /dev/null 2>&1
	fi

	dpkg -S `which shodan` > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install shodan..."
		sudo apt install shodan -y > /dev/null 2>&1
	fi

	user=$(whoami)

	ls /home/$user/go/bin/subfinder > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install subfinder..."
		go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest > /dev/null 2>&1
	fi

	ls /home/$user/go/bin/subjack > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install subjack..."
		go install github.com/haccer/subjack@latest > /dev/null 2>&1
	fi

	ls /home/$user/go/bin/gowitness > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install gowitness..."
		go install github.com/sensepost/gowitness@latest > /dev/null 2>&1
	fi

	ls /home/$user/go/bin/waybackurls > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[+] Install waybackurls..."
		go install github.com/tomnomnom/waybackurls@latest > /dev/null 2>&1
	fi

	echo "[+] You are good to go!"
	exit 0
}

function goWhois() {
	if [ ! -d "$TARGET/whois" ];
	then
		mkdir $TARGET/whois
	fi

	echo "[+] Printing domain information with whois..."
	whois $TARGET > $TARGET/whois/whois.txt
}

function goAssetfinder() {
	if [ ! -d "$TARGET/assetfinder" ];
	then
		mkdir $TARGET/assetfinder
	fi

	echo "[+] Harvesting subdomains with assetfinder..."
	assetfinder $TARGET > $TARGET/assetfinder/tmp.txt
	cat $TARGET/assetfinder/tmp.txt | grep "$TARGET" | sort -u > $TARGET/assetfinder/assetfinder.txt
	rm $TARGET/assetfinder/tmp.txt
}

function goSubfinder() {
	if [ ! -d "$TARGET/subfinder" ];
	then
		mkdir $TARGET/subfinder
	fi

	echo "[+] Harvesting subdomains with subfinder..."
	subfinder -d $TARGET -o $TARGET/subfinder/subfinder.txt > /dev/null 2>&1
}

function _mergeAssets() {
	if [ ! -d "$TARGET/mergeAssets" ];
	then
		mkdir $TARGET/mergeAssets
	fi

	echo "[+] Merge assets from assetfinder and subfinder..."
	cp $TARGET/assetfinder/assetfinder.txt $TARGET/mergeAssets/tmp.txt
	cat $TARGET/subfinder/subfinder.txt >> $TARGET/mergeAssets/tmp.txt
	cat $TARGET/mergeAssets/tmp.txt | sort -u > $TARGET/mergeAssets/mergeAssets.txt
	rm $TARGET/mergeAssets/tmp.txt
}

function goSubjack() {
	if [ ! -d "$TARGET/subjack" ];
	then
		mkdir $TARGET/subjack
	fi

	if [ ! -f "$TARGET/fingerprints.json" ];
	then
		wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O $TARGET/subjack/fingerprints.json > /dev/null 2>&1
	fi

	echo "[+] Checking for possible subdomain takeover..."
	if [ ! -f "$TARGET/subjack/subjack.txt" ];
	then
		touch $TARGET/subjack/subjack.txt
	fi
	subjack -w $TARGET/mergeAssets/mergeAssets.txt -c $TARGET/subjack/fingerprints.json -o $TARGET/subjack/subjack.txt -t 100 -timeout 30 -ssl -v -m > /dev/null 2>&1
}

function goHttprobe() {
	if [ ! -d "$TARGET/httprobe" ];
	then
		mkdir $TARGET/httprobe
	fi

	echo "[+] Probing for alive domains (HTTP/HTTPS) with httprobe..."
	cat $TARGET/mergeAssets/mergeAssets.txt | httprobe --prefer-https | sed 's/https\?:\/\///' > $TARGET/httprobe/tmp.txt
	sort -u $TARGET/httprobe/tmp.txt > $TARGET/httprobe/httprobe.txt
	rm $TARGET/httprobe/tmp.txt
}

function goWhatweb() {
	if [ ! -d "$TARGET/whatweb" ];
	then
		mkdir $TARGET/whatweb
	fi

	echo "[+] Getting web sites overview with whatweb..."
	whatweb --input-file $TARGET/httprobe/httprobe.txt --quiet --no-errors --max-threads 50 --log-brief="$TARGET/whatweb/whatweb.txt"
}

function goGowitness() {
	if [ ! -d "$TARGET/gowitness" ];
	then
		mkdir $TARGET/gowitness
	fi

	echo "[+] Taking screenshots with gowitness..."
	gowitness file -f ../httprobe/httprobe.txt -P $TARGET/gowitness -t 5 --disable-db --disable-logging
}

function goNmap() {
	if [ ! -d "$TARGET/nmap" ];
	then
		mkdir $TARGET/nmap
	fi

	echo "[+] Nmap scanning for open ports..."
	nmap -T4 -iL $TARGET/httprobe/httprobe.txt -oN $TARGET/nmap/nmap.txt > /dev/null
}


function goWaybackurls() {
	if [ ! -d "$TARGET/waybackurls" ];
	then
		mkdir $TARGET/waybackurls
	fi

	echo "[+] Running waybackurls..."
	cat $TARGET/mergeAssets/mergeAssets.txt | waybackurls > $TARGET/waybackurls/tmp.txt
	sort -u $TARGET/waybackurls/tmp.txt > $TARGET/waybackurls/waybackurls.txt
	rm $TARGET/waybackurls/tmp.txt 
	
	params=".aspx|.asp|.php|.html|.jspx|.jsp|.json|.js|.xml|.pdf|.docx|.doc|.xlsx|.xls|.txt"	
	echo "[+] Filtering for interesting file extensions..."
	cat $TARGET/waybackurls/waybackurls.txt | egrep -e $params | sort -u > $TARGET/waybackurls/waybackurls_params.txt

	echo "[+] Sorting the interesting files from waybackurls considering the extension..."
	for line in $(cat $TARGET/waybackurls/waybackurls_params.txt);
	do
		case $line in
			*".aspx"*)
			echo $line >> $TARGET/waybackurls/tmp_aspx.txt
			;;

			*".asp"*)
			echo $line >> $TARGET/waybackurls/tmp_asp.txt
			;;

			*".php"*)
			echo $line >> $TARGET/waybackurls/tmp_php.txt
			;;

			*".html"*)
			echo $line >> $TARGET/waybackurls/tmp_html.txt
			;;

			*".jspx"*)
			echo $line >> $TARGET/waybackurls/tmp_jspx.txt
			;;

			*".jsp"*)
			echo $line >> $TARGET/waybackurls/tmp_jsp.txt
			;;

			*".json"*)
			echo $line >> $TARGET/waybackurls/tmp_json.txt
			;;

			*".js"*)
			echo $line >> $TARGET/waybackurls/tmp_js.txt
			;;

			*".xml"*)
			echo $line >> $TARGET/waybackurls/tmp_xml.txt
			;;

			*".pdf"*)
			echo $line >> $TARGET/waybackurls/tmp_pdf.txt
			;;

			*".docx"*)
			echo $line >> $TARGET/waybackurls/tmp_docx.txt
			;;

			*".doc"*)
			echo $line >> $TARGET/waybackurls/tmp_doc.txt
			;;

			*".xlsx"*)
			echo $line >> $TARGET/waybackurls/tmp_xlsx.txt
			;;

			*".xls"*)
			echo $line >> $TARGET/waybackurls/tmp_xls.txt
			;;

			*".txt"*)
			echo $line >> $TARGET/waybackurls/tmp_txt.txt
			;;
		esac
	done

	if [ -f "$TARGET/waybackurls/tmp_aspx.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_aspx.txt > $TARGET/waybackurls/aspx.txt
	fi
	
	if [ -f "$TARGET/waybackurls/tmp_asp.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_asp.txt > $TARGET/waybackurls/asp.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_php.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_php.txt > $TARGET/waybackurls/php.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_js.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_js.txt > $TARGET/waybackurls/js.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_html.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_html.txt > $TARGET/waybackurls/html.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_jspx.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_jspx.txt > $TARGET/waybackurls/jspx.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_jsp.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_jsp.txt > $TARGET/waybackurls/jsp.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_json.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_json.txt > $TARGET/waybackurls/json.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_xml.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_xml.txt > $TARGET/waybackurls/xml.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_pdf.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_pdf.txt > $TARGET/waybackurls/pdf.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_docx.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_docx.txt > $TARGET/waybackurls/docx.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_doc.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_doc.txt > $TARGET/waybackurls/doc.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_xlsx.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_xlsx.txt > $TARGET/waybackurls/xlsx.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_xls.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_xls.txt > $TARGET/waybackurls/xls.txt
	fi

	if [ -f "$TARGET/waybackurls/tmp_txt.txt" ];
	then
		sort -u $TARGET/waybackurls/tmp_txt.txt > $TARGET/waybackurls/txt.txt
	fi

	rm $TARGET/waybackurls/tmp_*	
}

function goShodan() {
	local hostname=$(echo $TARGET | rev | cut -d '.' -f -2 | rev)
	echo $hostname
	local organization=$(echo $TARGET | rev | cut -d '.' -f 2 | rev)
	echo $organization

	if [ -z "$KEY" ];
	then
		echo "[-] No Shodan API KEY Provided, exit."
		return
	fi
	echo "[+] Start Shodan searching for hostname..."

	if [ ! -d "$TARGET/shodan" ];
	then
		mkdir $TARGET/shodan
	fi
	
	shodan init "$KEY" > /dev/null 2>&1
	if [ $? -ne 0 ];
	then
		echo "[-] Invalid Shodan API KEY, exit."
		return
	fi

	shodan download --limit -1 $TARGET/shodan/hostname.json.gz hostname:$hostname > /dev/null 2>&1
	shodan download --limit -1 $TARGET/shodan/organization.json.gz organization:$organization > /dev/null 2>&1
}

function printHelp() {
  cat << EOF
Usage: allInOne.sh [--help] [--install] --target TARGET [--key KEY]

AllInOne bash script for Reconnaissance which combines different tools to harvest information about the target.

Arguments:
	--help					Show this help message and exit
	--install				Install and check dependencies
	--target target				Target domain
	--key KEY				Shodan API KEY

EOF
  exit 1
}

function main() {
	while [ $# -gt 0 ]; do
	  case $1 in
		  --target)
				TARGET="$2"
				shift
				shift
		  ;;
		  --key)
				KEY="$2"
				shift
				shift
		  ;;
		  --install)
				installDependencies
		  ;;
		  --help)
				printHelp
		  ;;
		  -*)
				echo "[-] Unknown argument '$1'" && exit 1
		  ;;
		  *)
				ARGS+=("$1")
				shift
		  ;;
	  esac
  	done

	if [ -z $TARGET ];
	then
		echo "[-] Target can not be empty. Exiting..."
		exit 1
	fi

	echo "[+] Start AllInOne Reconnassaince..."
	if [ ! -d "$TARGET" ];
	then
		mkdir $TARGET
	fi

	goWhois
	goAssetfinder
	goSubfinder
	_mergeAssets
	goSubjack
	goHttprobe
	goWhatweb
	goGowitness
	goNmap
	goWaybackurls
	goShodan
	echo "[+] Good luck reviewing the results!"
	exit 0
}

main "$@"
