import os
import datetime, time
import json

from eth_utils import to_bytes

from twisted.internet.defer import inlineCallbacks
from twisted.internet.threads import deferToThread

import treq

from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cpchain.chain.trans import BuyerTrans, SellerTrans, ProxyTrans
from cpchain.chain import poll_chain
from cpchain.chain.utils import default_web3
from cpchain.utils import join_with_root, config
from cpchain.chain.models import OrderInfo
from cpchain.proxy.msg.trade_msg_pb2 import Message, SignMessage
from cpchain.proxy.client import start_client, download_file
from cpchain.wallet.db import BuyerFileInfo
from cpchain.wallet.fs import publish_file_update, session, FileInfo, decrypt_file_aes, add_file
from cpchain import crypto
from cpchain.crypto import Encoder


class MarketClient:
    def __init__(self, main_wnd):
        self.main_wnd = main_wnd

        self.url = config.market.market_url
        private_key_file_path = join_with_root(config.wallet.private_key_file)
        password_path = join_with_root(config.wallet.private_key_password_file)

        with open(password_path) as f:
            password = f.read()
        self.priv_key, self.pub_key = crypto.ECCipher.geth_load_key_pair_from_private_key(private_key_file_path, password)
        self.token = ''
        self.nonce = ''
        self.message_hash = ''

    @staticmethod
    def str_to_timestamp(s):
        return s #str(int(time.mktime(datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").timetuple())))

    @inlineCallbacks
    def login(self):
        header = {'Content-Type': 'application/json'}
        data = {'public_key': self.pub_key}
        try:
            resp = yield treq.post(url=self.url+'login/', headers=header, json=data, persistent=False)
            confirm_info = yield treq.json_content(resp)
            print(confirm_info)
            self.nonce = confirm_info['message']
            print('login succeed')
        except Exception as err:
            print(err)

        try:
            signature = crypto.ECCipher.geth_sign(self.priv_key, self.nonce)
            header_confirm = {'Content-Type': 'application/json'}
            data_confirm = {'public_key': self.pub_key, 'code': signature}
            resp = yield treq.post(self.url + 'confirm/', headers=header_confirm, json=data_confirm, persistent=False)
            confirm_info = yield treq.json_content(resp)
            print(confirm_info)
            self.token = confirm_info['message']
            print('login confirmed')
        except Exception as err:
            print(err)
        return confirm_info['message']


    @inlineCallbacks
    def publish_product(self, selected_id, title, description, price, tags, start_date, end_date, file_md5):
        header = {'Content-Type': 'application/json'}
        header['MARKET-KEY'] = self.pub_key
        header['MARKET-TOKEN'] = self.token
        data = {'owner_address': self.pub_key, 'title': title, 'description': description, 'price': price,
                'tags': tags, 'start_date': start_date, 'end_date': end_date, 'file_md5': file_md5}
        signature_source = str(self.pub_key) + str(title) + str(description) + str(price) + MarketClient.str_to_timestamp(start_date) + MarketClient.str_to_timestamp(end_date) + str(file_md5)
        signature = crypto.ECCipher.geth_sign(self.priv_key, signature_source)
        data['signature'] = signature
        resp = yield treq.post(self.url + 'product/publish/', headers=header, json=data)
        confirm_info = yield treq.json_content(resp)
        print(confirm_info)
        print('publish succeed')
        self.message_hash = confirm_info['data']['market_hash']
        publish_file_update(self.message_hash, selected_id)
        print(self.message_hash)
        return confirm_info['status']

    @inlineCallbacks
    def change_product_status(self, status):
        header = {'Content-Type': 'application/json', 'MARKET-KEY': self.pub_key, 'MARKET-TOKEN': self.token}
        data = {'status': status}
        import treq
        resp = yield treq.post(url=self.url+'product_change', headers=header, json=data)
        confirm_info = yield treq.json_content(response=resp)
        if confirm_info['success'] == False:
            print('publish failed')

    @inlineCallbacks
    def query_product(self, keyword):
        header = {'Content-Type': 'application/json'}
        url = self.url + 'product/search/?keyword=' + str(keyword)
        resp = yield treq.get(url=url, headers=header)
        confirm_info = yield treq.json_content(resp)
        print('product info: ')
        print(confirm_info)
        return confirm_info

    @inlineCallbacks
    def logout(self):
        header = {'Content-Type': 'application/json', 'MARKET-KEY': self.pub_key, 'MARKET-TOKEN': self.token}
        data = {'public_key': self.pub_key, 'token': self.token}
        import treq
        resp = yield treq.post(url=self.url+'logout', headers=header, json=data)
        confirm_info = yield treq.json_content(resp)
        print(confirm_info)


class BuyerChainClient:

    def __init__(self, main_wnd, market_client):
        self.main_wnd = main_wnd
        self.market_client = market_client

        self.buyer = BuyerTrans(default_web3, config.chain.core_contract)
        self.order_id_list = []

    def buy_product(self, msg_hash, file_title):
        desc_hash = crypto.Encoder.str_to_base64_byte(msg_hash)
        rsa_key = crypto.RSACipher.load_public_key()
        product = OrderInfo(
            desc_hash=desc_hash,
            buyer_rsa_pubkey=rsa_key,
            seller=self.buyer.web3.eth.defaultAccount,
            proxy=self.buyer.web3.eth.defaultAccount,
            secondary_proxy=self.buyer.web3.eth.defaultAccount,
            proxy_value=10,
            value=20,
            time_allowed=1000
        )
        print('product:')
        print(product)

        d = deferToThread(self.buyer.place_order, product)

        def cb(order_id):
            self.order_id_list.append(order_id)
            print("Before new buyer file info. ")
            new_buyer_file_info = BuyerFileInfo(order_id=order_id, market_hash=Encoder.bytes_to_base64_str(desc_hash),
                                                file_title=file_title, is_downloaded=False)
            add_file(new_buyer_file_info)
            self.update_treasure_pane()
            print('In place order callback order id: ', self.order_id_list)
        d.addCallback(cb)

        return self.order_id_list

    def withdraw_order(self, order_id):
        tx_hash = self.buyer.withdraw_order(order_id)
        print('withdraw order: ', tx_hash)
        return tx_hash

    def confirm_order(self, order_id):
        tx_hash = self.buyer.confirm_order(order_id)
        print('confirm order: ', tx_hash)
        return tx_hash

    def dispute(self, order_id):
        tx_hash = self.buyer.dispute(order_id)
        print('start a dispute: ', tx_hash)
        return tx_hash

    def check_confirm(self):
        if len(self.order_id_list) > 0:
            for current_id in self.order_id_list:
                state = self.buyer.query_order(current_id)[10]
                if state == 1:
                    print('proxy confirmed')
                    self.send_request(current_id)
                    return state
                else:
                    print('proxy not confirmed')
                    return state
        else:
            print('no placed order')

    def update_treasure_pane(self):
        from PyQt5.QtWidgets import QWidget
        content_tabs = self.main_wnd.content_tabs
        wid = content_tabs.findChild(QWidget, "treasure_tab")
        wid.update_table()

    def send_request(self, order_id):
        new_order_info = self.buyer.query_order(order_id)
        message = Message()
        buyer_data = message.buyer_data
        message.type = Message.BUYER_DATA
        buyer_data.order_id = order_id
        buyer_data.seller_addr = to_bytes(hexstr=new_order_info[3])
        buyer_data.buyer_addr = to_bytes(hexstr=new_order_info[2])
        buyer_data.market_hash = new_order_info[0]

        sign_message = SignMessage()
        sign_message.public_key = Encoder.str_to_base64_byte(self.market_client.pub_key)
        sign_message.data = message.SerializeToString()
        sign_message.signature = crypto.ECCipher.generate_signature(
            Encoder.str_to_base64_byte(self.market_client.priv_key),
            sign_message.data
        )
        d = start_client(sign_message)

        def update_buyer_db(file_uuid, file_path, new_order_id):
            market_hash = Encoder.bytes_to_base64_str(self.buyer.query_order(new_order_id)[0])
            session.query(BuyerFileInfo).filter(BuyerFileInfo.order_id == order_id). \
                update({BuyerFileInfo.market_hash: market_hash,
                        BuyerFileInfo.is_downloaded: True,
                        BuyerFileInfo.file_uuid: file_uuid,
                        BuyerFileInfo.path: file_path,
                        BuyerFileInfo.size: os.path.getsize(file_path)
                        }, synchronize_session=False)
            session.commit()
            return market_hash

        def buyer_request_proxy_callback(message):
            print("Inside buyer request callback.")
            assert message.type == Message.PROXY_REPLY
            proxy_reply = message.proxy_reply

            if not proxy_reply.error:
                print('file_uuid: %s' % proxy_reply.file_uuid)
                print('AES_key: ')
                print(len(proxy_reply.AES_key))
                print(proxy_reply.AES_key)
                file_dir = os.path.expanduser(config.wallet.download_dir)
                file_path = os.path.join(file_dir, proxy_reply.file_uuid)
                print(file_path)
                decrypted_file = decrypt_file_aes(file_path, proxy_reply.AES_key)
                print('Decrypted file path ' + str(decrypted_file))

                update_buyer_db(proxy_reply.file_uuid, decrypted_file, order_id)
                self.update_treasure_pane()
                
                self.confirm_order(order_id)
                self.order_id_list.remove(order_id)

            else:
                print(proxy_reply.error)

        d.addBoth(buyer_request_proxy_callback)


class SellerChainClient:
    def __init__(self, main_wnd, market_client):
        self.main_wnd = main_wnd
        self.market_client = market_client

        self.seller = SellerTrans(default_web3, config.chain.core_contract)
        start_id = self.seller.get_order_num()
        self.monitor = poll_chain.OrderMonitor(start_id, self.seller)

    def query_new_order(self):
        new_order_list = self.monitor.get_new_order()
        print('new orders: ', new_order_list)
        return new_order_list

    def claim_timeout(self, order_id):
        tx_hash = '0xand..'
        print('claim timeout: ', tx_hash)
        return tx_hash

    def send_request(self):
        new_order = self.query_new_order()
        if len(new_order) != 0:
            for new_order_id in new_order:
                new_order_info = self.seller.query_order(new_order_id)
                print('In seller send request: new oder infomation:')
                market_hash = new_order_info[0]
                buyer_rsa_pubkey = new_order_info[1]
                raw_aes_key = session.query(FileInfo.aes_key)\
                    .filter(FileInfo.market_hash == Encoder.bytes_to_base64_str(market_hash))\
                    .all()[0][0]
                encrypted_aes_key = load_der_public_key(buyer_rsa_pubkey, backend=default_backend()).encrypt(
                    raw_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print("Encrypted_aes_key length" + str(len(encrypted_aes_key)))
                storage_type = Message.Storage.IPFS
                ipfs_gateway = config.proxy.default_ipfs_gateway
                file_hash = session.query(FileInfo.hashcode)\
                    .filter(FileInfo.market_hash == Encoder.bytes_to_base64_str(market_hash))\
                    .all()[0][0]
                message = Message()
                seller_data = message.seller_data
                message.type = Message.SELLER_DATA
                seller_data.order_id = new_order_id
                seller_data.seller_addr = to_bytes(hexstr=new_order_info[3])
                seller_data.buyer_addr = to_bytes(hexstr=new_order_info[2])
                seller_data.market_hash = market_hash
                seller_data.AES_key = encrypted_aes_key
                storage = seller_data.storage
                storage.type = storage_type
                ipfs = storage.ipfs
                ipfs.file_hash = file_hash.encode('utf-8')
                ipfs.gateway = ipfs_gateway
                sign_message = SignMessage()
                sign_message.public_key = Encoder.str_to_base64_byte(self.market_client.pub_key)
                sign_message.data = message.SerializeToString()
                sign_message.signature = crypto.ECCipher.generate_signature(
                    Encoder.str_to_base64_byte(self.market_client.priv_key),
                    sign_message.data
                )
                d = start_client(sign_message)
                d.addBoth(self.seller_deliver_proxy_callback)

    def seller_deliver_proxy_callback(self, message):
        print("Inside seller request callback.")
        assert message.type == Message.PROXY_REPLY

        proxy_reply = message.proxy_reply

        if not proxy_reply.error:
            print('file_uuid: %s' % proxy_reply.file_uuid)
            print('AES_key: ')
            print(proxy_reply.AES_key)
        else:
            print(proxy_reply.error)


class ProxyChainClient:

    def __init__(self):
        self.proxy = ProxyTrans(default_web3, config.chain.core_contract)

    def proxy_confirm(self):
        print('proxy claim relay')
        self.proxy.claim_relay(5, bytes([0, 1, 2, 3] * 8))


proxy_chain_client = ProxyChainClient()
