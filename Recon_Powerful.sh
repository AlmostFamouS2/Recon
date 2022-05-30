#!/usr/bin/bash

if [[ "$1" == "-h" ]];then
    echo -e "argv 1 for target and argv 2 you use 'yes/no' if you want sub-sub scan"
fi

echo -e "\033[35m[*]\033[0mSTARTING MEGA RECON IN $1"
echo -e "\033[35m[*]\033[0m => Starting Assetfinder"
assetfinder $1 -subs-only 1>>assetscan
echo -e "\033[35m[*]\033[0m => Starting sublist3r"
#sublist3r -n -o sublistscan -d $1
echo -e "\033[35m[*]\033[0m => Starting subfinder"
subfinder -silent -d $1 1>>subfindersubs
echo -e "\033[35m[*]\033[0m => Starting cert"
curl -s "https://crt.sh/?q=%.$1&output=json" | jq -r ".[].name_value" | sed "s/\*\.//g" >> certsubs
curl -s "https://crt.sh/?q=%.%.$1&output=json" | jq -r ".[].name_value" | sed "s/\*\.//g" >> certsubs
curl -s "https://crt.sh/?q=%.%.%.$1&output=json" | jq -r ".[].name_value" | sed "s/\*\.//g" >> certsubs
curl -s "https://crt.sh/?q=%.%.%.%.$1&output=json" | jq -r ".[].name_value" | sed "s/\*\.//g" >> certsubs
curl -s "https://crt.sh/?q=%.%.%.%.%.$1&output=json" | jq -r ".[].name_value" | sed "s/\*\.//g" >> certsubs
echo -e "\033[35m[*]\033[0m => Starting haktrails"
echo $1 | haktrails subdomains 1>>haksubs
echo -e "\033[35m[*\033[0m => Starting anubis"
anubis -t $1 --silent -a -o anusubs
echo -e "\033[35m[*]\033[0m => Starting findomain"
findomain-linux -q -t $1 1>>findosubs
echo -e "\033[35m[*]\033[0m => Starting github-subdomains"
python3 /root/tools/github-search/github-subdomains.py -d $1 -t YOURGITHUBTOKEN | anew gitsubs
echo -e "\033[35m[*]\033[0m => Starting Chaos"
chaos -d $1 -o chasubs
echo -e "\033[35m[*]\033[0m => Starting SonarByte(rapiddns)"
sonarbyte -d $1 | anew sonarb
# echo -e "\033[35m[*]\033[0m => Starting git-search"
# git-search -d $1 1>>gits
echo -e "\033[35m[*]\033[0m => Starting Amass Enum"
amass enum -d $1 -passive -nocolor 1>>amass1
echo -e "\033[36m[*]\033[0m => Starting MODE 2 FULL"
curl --silent --insecure --tcp-fastopen --tcp-nodelay "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://api.hackertarget.com/hostsearch/?q=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://certspotter.com/api/v0/certs?domain=$1 | grep  -o '\[\".*\"\]' | sed -e 's/\[//g' | sed -e 's/\"//g' | sed -e 's/\]//g' | sed -e 's/\,/\n/g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt &
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://spyse.com/target/domain/$1 | grep -E -o "button.*>.*\.$1\/button>" |  grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://tls.bufferover.run/dns?q=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://dns.bufferover.run/dns?q=.$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://urlscan.io/api/v1/search/?q=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay -X POST https://synapsint.com/report.php -d "name=http%3A%2F%2F$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://jldc.me/anubis/subdomains/$1 | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://sonar.omnisint.io/subdomains/$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay https://riddler.io/search/exportcsv?q=pld:$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt 
curl --silent --insecure --tcp-fastopen --tcp-nodelay -X POST https://suip.biz/?act=amass -d "url=$1&Submit1=Submit"  | grep $1 | cut -d ">" -f 2 | awk 'NF' >> tmp.txt
curl --silent --insecure --tcp-fastopen --tcp-nodelay -X POST https://suip.biz/?act=subfinder -d "url=$1&Submit1=Submit"  | grep $1 | cut -d ">" -f 2 | awk 'NF' >> tmp.txt
curl https://subbuster.cyberxplore.com/api/find?domain=$1 -s | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> tmp.txt
curl --silent --insecure --tcp-fastopen --tcp-nodelay "https://securitytrails.com/list/apex_domain/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".$1" | sort -u >> tmp.txt
echo -e "\033[35m[*]\033[0m => Removing Duplicates"
cat assetscan tmp.txt sublistscan sonarb anusubs gitsubs subfindersubs certsubs haksubs chasubs findosubs amass1 | anew unresolvedallsubs
rm -rf anusubs gitsubs sonarb assetscan sublistscan subfindersubs certsubs haksubs findosubs chasubs amass1 certing tmp.txt
echo -e "\033[35m[*]\033[0m => Starting httpx"
cat unresolvedallsubs | dnsgen - >> dnsg
cat unresolvedallsubs dnsg | anew | httpx -title -ports 80,8080,443 -server -silent -threads 500 -status-code 1>>resolvedsubs
cat resolvedsubs | grep "200" | awk '{print $1}' 1>>200responses
echo -e "\033[35m[*]\033[0m => Extracting IPs"
cat resolvedsubs | awk '{print $1}' | dnsx -silent -resp-only | anew dnsx.txt
if [[ "$2" == "yes" ]];then
    echo -e "\033[35m[*]\033[0m => Starting Sub-subdomains enumeration"
    cat resolvedsubs | awk '{print $1}' | anew osubs
    findomain-linux -f osubs -q -u findosubsubscan --threads 300
    subfinder -dL osubs -o subfscan -silent
    cat osubs | assetfinder -subs-only | anew assetsubsub
    cat osubs | haktrails subdomains | anew haksubsub
    cat osubs | xargs -I{} sh -c "curl -s 'https://crt.sh/?q=%.{}&output=json' | jq -r '.[].name_value' | sed 's/\*\.//g' | anew certsubsub"
    cat findosubsubscan subfscan assetsubsub haksubsub certsubsub | anew subsubscan ; rm findosubsub subfscan assetsubsub haksubsub certsubsub
else
    echo -e "\033[35m[*]\033[0m => Skipping Sub-subdomains enumeration"
fi
echo -e "\033[35m[*]\033[0m => Starting Checking for 404 Subs"
cat resolvedsubs | grep "404" | awk '{print $1}' 1>>404takeover
