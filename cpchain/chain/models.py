import collections

order_fields = ['desc_hash', 'buyer_rsa_pubkey', 'seller', 'proxy', 'secondary_proxy', 'proxy_value', 'value', 'time_allowed']
OrderInfo = collections.namedtuple('OrderInfo', order_fields)
