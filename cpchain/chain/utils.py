import json

from web3 import Web3, IPCProvider, TestRPCProvider, HTTPProvider
from eth_keyfile import extract_key_from_keyfile

from cpchain import config
from cpchain.utils import join_with_root


class DefaultWeb3:
    def __init__(self):
        self.web3 = None

    def _set_web3(self):
        if self.web3 is None:
            mode = config.chain.mode
            if mode == "test":
                provider = TestRPCProvider()
            elif mode == "falcon":
                provider = HTTPProvider(config.chain.falcon_provider_addr)
            else:
                provider = IPCProvider(join_with_root(config.chain.ipc_provider_addr))
            self.web3 = Web3(provider)
            self.web3.eth.defaultAccount = self.web3.eth.accounts[0]

    def __getattr__(self, name):
        self._set_web3()
        return getattr(self.web3, name)


default_web3 = DefaultWeb3()


def read_contract_interface(contract_name):

    with open(join_with_root(config.chain.contract_json)) as f:
        all_contracts = json.load(f)
        contract_interface = all_contracts['<stdin>:' + contract_name]
    return contract_interface


def read_contract_address(contract_name):
    with open(join_with_root(config.chain.registrar_json)) as f:
        contracts = json.load(f)
    return contracts[contract_name]


def deploy_contract(contract_name, web3=default_web3):
    contract_interface = read_contract_interface(contract_name)
    new_contract = web3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
    tx_hash = new_contract.deploy(transaction={'from': web3.eth.accounts[0]})
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    contract_address = tx_receipt['contractAddress']
    with open(config.chain.registrar_json, 'w') as f:
        f.write(json.dumps(dict({contract_name: contract_address})))
    new_contract.address = contract_address
    return new_contract


def load_private_key_from_keystore(key_path, password='password'):
    key_bytes = extract_key_from_keyfile(key_path, password)
    return key_bytes
