import os
import sys
from colorama import Fore
import time
from datetime import datetime
import attack
import fakeAP


def bash(command: str):
    """
     execute bash command
    :param command represent the bash command we want to execute
    """
    return os.system(command)


def print_regular(message: str):
    print('{}{}'.format(Fore.WHITE, message))


def print_command(message: str):
    print('{}{}'.format(Fore.BLUE, message))
    print(Fore.RESET)


def print_errors(message: str):
    print('{}{}'.format(Fore.RED, message))
    print(Fore.RESET)


def print_header(message: str):
    print(Fore.WHITE)
    bash('figlet -f slant {}'.format(message))

def print_sub_header(message: str):
    print(Fore.GREEN)
    bash('figlet -f digital {}'.format(message))
    print(Fore.RESET)

def exit_and_cleanup(exit_code, message):
    print_regular(Fore.YELLOW + '\n[*] Perform cleanup')
    os.system('sudo sh Templates/cleanup.sh')
    sys.exit(Fore.LIGHTYELLOW_EX + '{} Perform exit() with exit code {} , {}'.format(Fore.WHITE, exit_code, message))


def run_attack():
    """
        Let's start the attack
    """
    attacker = attack.Attack()
    target_ap = attacker.network_search()
    print(Fore.BLUE + "[*] you choose: {}".format(target_ap))
    #target_client = attacker.client_search(target_ap)
    #print_regular('The target you choose to attack: {}'.format(target_client))
    attacker.create_fakeAP()
    

def run():
    print_header("EvilTwin runner")
    print_command("Welcome To EvilTwin Runner")

    if os.geteuid() != 0:
        sys.exit('{}Error: This script must be run as root.'.format(Fore.RED))

    while True:
        user_input = input('{}\n(1) Perform Evil Twin Attack\n'
                 '(2) Perform Defence on Evil Twin Attack \n'
                 '(3) CleanUp'
                 'Please select one of the options mentioned above, or write quit to quit the manager\n\n'.format(
                    Fore.BLUE))
        if user_input == '1':
            run_attack()
            break
        else:
            print_errors('Not a valid option, try again please.')
    

if __name__ == '__main__':
    run()



