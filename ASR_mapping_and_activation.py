from multiprocessing import Pool
from multiprocessing import cpu_count
import argparse
import os
from socket import gethostname, gethostbyname
import paramiko
import getpass
from wallet import Wallet
from Log import Log
from ilom_config_with_asr import ILOMHost as Ilom_fun
from ilom.configure import Ilom
from ipaddress import ip_address, ip_network
# import signal
import socket
import re
import _thread
from cryptography.fernet import InvalidToken
from time import time
from datetime import timedelta

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-iH', '--target', type=argparse.FileType('r', encoding='UTF-8'),
                        help='File with the list of machines to ASR activation for ILOM '
                             'configured HOSTS. This can'
                             'contain one IP/FQDN per line and the software will '
                             'guess at the shortname for the database insert. Two '
                             'comma separated values are also allowed. The first '
                             'being the target and the second the shortname. '
                             'Mixing these two formats in the same file is also '
                             'allowed.')
    parser.add_argument('-iA', '--asr_data', type=argparse.FileType('r', encoding='UTF-8'), required=True,
                        help="give the csv file of ASR DATA as input")
    parser.add_argument('-o', '--output', default='csv', help='asr_activation_log output in csv format:')
    parser.add_argument('-iwi', '--wallet_Ilom', type=argparse.FileType('r', encoding='UTF-8'), required=True,
                        help="pass your ILOM passwords.wallet file")
    parser.add_argument('-iwa', '--wallet_ASR', type=argparse.FileType('r', encoding='UTF-8'), required=True,
                        help="pass your ASR passwords.wallet file")
    parser.add_argument('-w', '--workers', type=int, default=cpu_count() * 16, help='default:cpu_count*16')
    args = parser.parse_args()
    try:
        args.job_username = os.environ['USERNAME']
    except KeyError:
        args.job_username = os.environ['USER']

    if args.job_username is None:
        args.job_username = getpass.getuser()
    args.job_hostname = gethostname()
    return args


def get_config(wallet_input, password=None):
    """Load & decrypt the configuration.

    The wallet should be created with ASR_MAPPING_WALLET.py

    Args:
        wallet_input: encrypted wallet is to be given as input.
        password (str): Used to unlock the configuration wallet.

    Returns (dict):
        Returns a dict that contains:
            passwords(list)
            config(dict)

    Raises:
        InvalidToken: Raised for a bad decryption password.
        ValueError: Raised for an empty or invalid wallet.
    """

    try:
        encrypted = Wallet(password)
        decrypted = encrypted.load(wallet_input)
    except InvalidToken:
        raise InvalidToken('Bad password.')
    # except InvalidToken:
    #     raise InvalidToken('Bad password.')

    if decrypted is not None:
        if not isinstance(decrypted, dict) or len(decrypted) == 0:
            raise ValueError('Wallet not created with ASR_MAPPING_WALLET.py')
        if not isinstance(decrypted['passwords'], list) or len(decrypted['passwords']) == 0:
            raise ValueError('No passwords in the wallet.')
    return decrypted


def asr_list(asrdata):
    """

    Args:
        asrdata: A csv file that contains ASR subnets and hostnames in two column

    Returns: A dictionary with subnet as key and hostname as value

    """
    asr_map = dict()
    for line in asrdata:
        k = line.split(',')
        asr_map[ip_network(k[0])] = ((k[1]).strip())
    return asr_map


def parse_target(target):
    """Parse the target, looking for a single name or CSV.

    If target is a single value, return that value as the oob
    hostname and guess at the system shortname. If target is a
    CSV, use the first value as the hostname and the second as
    the shortname.

    Args:
        target(str): Either a single hostname or a CSV with
            hostname and a shortname

    Returns:
        (hostname(str), shortname(str)
    """
    try:
        _ = ip_address(target)
    except ValueError:
        target = target.rstrip()
        names = target.split(',')
        if len(names) == 2 and names[1] =='':
            del names[1]
        if len(names) == 1:
            short = names[0].split('.')[0]
            names.append(short.replace('-c', ''))
        return names
    else:
        return target, target


class AsrRegister:
    """
         Host configured with ILOM searchs for the nearest ASR manager listed in the asr_map.csv file.
        Mapping status will be written in the log file.
        Error in connection: If the appropiate ASR is found but unable to connect
        ILOM coniguration failed: writing the ASR details to ILOM is failed
        No ASR manager found: if No appropiate ASR is found in the given list.
    """

    def __init__(self, asr_map, wallet_ilom, wallet_asr):
        """
        Args:
             asr_map:  ASR hostnames and supernets in dict format
             wallet_ilom: Encrypted password list of ILOMs
             wallet_asr: Encrypted passwords of ASR managers

         Returns:
              data: A dictonary mentioning all the resultants
        """
        self.asr_map = asr_map
        self.wallet_Ilom = wallet_ilom
        self.wallet_ASR = wallet_asr
        self.data = dict()
        self.hostname = None
        self.interact = None

    def asr_activation(self, hostname):
        hostname, shortname = parse_target(hostname)
        self.hostname = hostname
        self.data['oob_name'] = hostname
        self.data['shortname'] = shortname
        if hostname == shortname:
            ip = ip_address(hostname)
        else:
            ip = ip_address(gethostbyname(hostname))

        # class TimeOutError(Exception):
        #     pass
        #
        # def handler(signum, frame):
        #     raise TimeOutError()
        #
        # signal.signal(signal.SIGALRM, handler)
        # signal.alarm(10)
        try:
            host = Ilom(hostname, self.wallet_Ilom)
            self.interact = host.open()
            self.data['model'] = host.model
            self.data['serial_number'] = host.serial_number
            name_list = self.data['oob_name'].split('.')
            self.data['domain'] = '.'.join(name_list[1:])
        except (TimeoutError, AttributeError):
            self.data['error'] = ['Ilom timeout error']
            self.data['asr_server'] = []
            self.data['asr_configured'] = 0
            return self.data
        except paramiko.ssh_exception.SSHException:
            self.data['error'] = ['Ilom Authentication error']
            self.data['asr_server'] = []
            self.data['asr_configured'] = 0
            return self.data
        except paramiko.ssh_exception.NoValidConnectionsError:
            self.data['error'] = ['Unable to connect to the port']
            self.data['asr_server'] = []
            self.data['asr_configured'] = 0
            return self.data
        # finally:
        #     signal.alarm(0)

        for supernet, asr_server in self.asr_map.items():
            if ip in supernet:
                if AsrRegister.process_host(self, asr_server):  # returns True if the ILOM is
                                                                # configured with ASR details
                    try:
                        s = paramiko.SSHClient()
                        s.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        s.load_system_host_keys()
                        for password in self.wallet_ASR:  # Tries for the correct password in the decrypted wallet
                            try:
                                s.connect(hostname=asr_server, username='root', password=password, timeout=20, banner_timeout=100)
                                break
                            except (paramiko.ssh_exception.SSHException, EOFError, TimeoutError):
                                pass
                        s.exec_command('asr activate_asset -i %s' % ip)
                        s.close()
                        self.data['asr_server'] = asr_server
                        self.data['asr_configured'] = 1
                        return self.data
                    except paramiko.AuthenticationException:
                        self.data['error'] = ['Unable to authenticate']
                        self.data['asr_server'] = asr_server
                        self.data['asr_configured'] = 0
                        return self.data
                    except (paramiko.ssh_exception.SSHException, socket.timeout) as e:
                        if re.search(r'\[Errno 104\]', str(e)):
                            self.data['error'] = 'Error reading SSH protocol banner'
                        elif str(e) != '':
                            self.data['error'] = "{}: {}".format(type(e).__name__, str(e))
                        else:
                            self.data['error'] = type(e).__name__
                        self.data['asr_configured'] = 0
                        return self.data
                else:
                    self.data['error'] = ['ILOM configuration failed']
                    self.data['asr_server'] = asr_server
                    self.data['asr_configured'] = 0
                    return self.data
            else:
                pass
        self.data['error'] = ['No ASR manager found']
        self.data['asr_server'] = []
        self.data['asr_configured'] = 0
        return self.data

    def process_host(self, asr_server):
        """

        Args:
            asr_server: ASR server IP that to be mapped

        Returns:
            True: if ILOM configured with ASR server details
            False: if ILOM configurtion failed with ASR server details

        """

    # import signal
        #
        # def handler(signum, frame):
        #     host.close()
        #     raise TimeOutError("Host alarm")
        #
        # logging.getLogger().setLevel(logging.INFO)
        # # signal.signal(signal.SIGALRM, handler)
        # # signal.alarm(60)
        if self.interact:
            try:
                k = Ilom_fun(self.interact, self.hostname)
                status = k.set_asr(str(asr_server), 15)
                if status:
                    return True
                else:
                    return False
            except TimeoutError:
                return False
        else:
            return False


def main():
    args = parse_args()
    result = asr_list(args.asr_data)
    try:
        pswd_wallet_ilom = os.environ['ILOM_wallet']
    except KeyError:
        print("Please type your wallet password and hit enter to continue.")
        pswd_wallet_ilom = getpass.getpass()

    try:
        pswd_wallet_asr = os.environ['ASR_wallet']
    except KeyError:
        pswd_wallet_asr = pswd_wallet_ilom

    start = time()
    wallet_ilom = get_config(args.wallet_Ilom, pswd_wallet_ilom)
    wallet_asr = get_config(args.wallet_ASR, pswd_wallet_asr)
    step = AsrRegister(result, wallet_ilom['passwords'], wallet_asr['passwords'])
    z = list()
    for ip_row_hostdata in args.target:
        z.append(ip_row_hostdata.rstrip())
    args.number_of_hosts = len(z)
    try:
        with Log(args, wallet_asr) as log:
            pool = Pool(args.workers)
            for k in range(0, len(z), 10):
                result = pool.imap_unordered(step.asr_activation, z[k:k+10])
                for data in result:
                    log.record(data)
                    print("{: 3.0f}%, {:d}+{:d} / {:d}: {}".format(
                        100.0 * (log.succeeded + log.failed) / log.total,
                        log.succeeded,
                        log.failed,
                        log.total,
                        data['oob_name']))
            pool.close()
    except (InvalidToken, ValueError, IndexError, TimeoutError, EOFError, socket.timeout,
            paramiko.ssh_exception.SSHException) as e:
        print(str(e))
        exit(1)
    print('Execution time (H:M:S.uS) {}'.format(timedelta(seconds=time() - start)))



if __name__ == "__main__":
    main()

