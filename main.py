# -*- coding: utf-8 -*-
from Account_Model.utils import *


class Client(object):
    #clients have public and private key
    def __init__(self):
        public_key, private_key = gen_key()
        self.public_key = public_key
        self.private_key = private_key

class Bank(Client):
    #banks have public and private key
    #including mint method
    def __init__(self):
        super().__init__()
        self.total_deposit = 0

    def mint(self, m):
        self.total_deposit += sum(m.values())
        m = serialize(m)
        signature = sign(m, self.private_key, 'SHA-256')
        validator.deposit(m, signature, self.public_key)

class CentralOperator(object):
    #central operator is the validator or server
    def __init__(self):
        self.public_key, self.private_key = gen_key()
        self.ledger = {}
        #nonce is like transaction record, to avoid recieving same msg twice
        self.nonces = {}
        self.bank_public_key = False

    def register_bank(self):
        #register the bank once so, make sure only one unique bank key
        if self.bank_public_key == False:
            print('Central Authority\nRegister new bank\n')
            bank = Bank()
            self.bank_public_key = bank.public_key
        else:
            print('Central Authority\nBank already registered\n')
        return bank

    def deposit(self, message, signature, key):
        #verify the signature is correct before deposit
        if verify_sig(message, signature, key):
            m = unserialize(message)
            for key, val in m.items():
                self.ledger[key] += val
                print('Central Authority\n--BANK DEPOSIT--\nUSER:{}\nDEPOSIT:{}\n'.format(names[key], val))
        else:
            #signature is not correct
            print('Central Authority\nFailed')

    def open_account(self, message, signature, public_key):
        #verify signature to open account
        if verify_sig(message, signature, public_key):
            #only open account once! otherwise it will erase deposits
            if public_key not in self.ledger.keys():
                # open new account with zero balance
                self.ledger[public_key] = 0
                #also open transactions with 0
                self.nonces[public_key] = 0
                print('Central Authority\n--NEW ACCOUNT--\nUSER:{}\n'.format(names[public_key]))
        else:
            print('Central Authority\nFailed')

    def get_balance(self, message, signature, public_key):
        #only with signature can you see your own balance
        if verify_sig(message, signature, public_key):
            #                 print('Central Authority\n--BALANCE-\nUSER:{}\nBALANCE:{}\n'.format(names[public_key],self.ledger[public_key]))
            balance = self.ledger[public_key]
            m = serialize(balance)
            signature = sign(m, self.private_key, 'SHA-256')
            return (m, signature, self.public_key)
        else:
            print('Central Authority\nFailed')

    def transfer(self, message, signature, public_key):
        if verify_sig(message, signature, public_key):
            m = unserialize(message)
            #this is the transaction ID, we want to check that its not a msged already recieved twice...
            transaction_nonce = m['nonce']
            #recepient name
            recipient = m['recepient']
            #recpient public key
            recipient_key = keys[recipient]
            amount = m['amount']

            client_nonce = self.nonces[public_key]
            client_balance = self.ledger[public_key]
            #check to see if your not sending yourself money
            if recipient_key != public_key:
                #check your sending a positive amount, otherwise you will withdrawl from others.
                if amount >= 0:
                    # check to see if it a new transaction
                    if client_nonce == transaction_nonce:
                        #check sufficient funds
                        if client_balance >= amount:
                            self.ledger[public_key] -= amount
                            self.ledger[recipient_key] += amount
                            print('Central Authority\n--TRANSFER-\nUSER:{}\nDEBIT:{}\nUSER:{}\nCREDIT:{}\n'.format(
                                names[public_key],
                                amount,
                                recipient,
                                amount))

                            m = True
                            # transfer succeeded update nonce
                            self.nonces[public_key] += 1
                        else:
                            print('Central Authority\nFailed', 'Insufficient Funds\n')
                            m = False
                    else:
                        print('Central Authority\nFailed, Duplicate Transaction\n')
                        m = False
                else:
                    print('Central Authority\nFailed amount {} is not positive value\n'.format(amount))
                    m = False
            else:
                print('Central Authority\nCannot send to yourself\n'.format(amount))
                m = False
        #response of failure or sucessful
        m = serialize(m)
        signature = sign(m, self.private_key, 'SHA-256')
        return (m, signature, self.public_key)


class User(Client):
    def __init__(self):
        super().__init__()
        self.nonce = 0

    def open_account(self):
        m = b''
        signature = sign(m, self.private_key, 'SHA-256')
        validator.open_account(m, signature, self.public_key)

    def check_balance(self):
        m = b''
        signature = sign(m, self.private_key, 'SHA-256')
        m, signature, public_key = validator.get_balance(m, signature, self.public_key)
        # make sure its the validator sending us msg
        if verify_sig(m, signature, public_key):
            balance = unserialize(m)
            print('{}\nChecks Balance\nSees balance of {}\n'.format(names[self.public_key], balance))

    def send_money(self, name, amount):
        print('{} wants to send {} to {}\n'.format(names[self.public_key], amount, name))
        key = keys[name]
        m = {'nonce': self.nonce, 'amount': amount, 'recepient': name}
        m = serialize(m)
        signature = sign(m, self.private_key, 'SHA-256')
        m, signature, public_key = validator.transfer(m, signature, self.public_key)
        # make sure its the validator sending us msg
        if verify_sig(m, signature, public_key):
            response = unserialize(m)
            if response:
                self.nonce += 1
                self.check_balance()
            else:
                print('Transfer failed\n')

if __name__ == "__main__":
    validator = CentralOperator()
    #genesis
    bank = validator.register_bank()

    #create users
    a = User()
    b =User()
    c =User()

    #for readibility do a mapping of names
    #If you want privacy should just use public key name
    names = {a.public_key:'Alice',b.public_key:'Bob',c.public_key:'Charlie'}
    keys = {'Alice':a.public_key,'Bob':b.public_key,'Charlie':c.public_key}

    #users open account
    a.open_account()
    b.open_account()
    c.open_account()

    #bank mints money
    deposits = {a.public_key:100,b.public_key:100,c.public_key:100}
    bank.mint(deposits)

    #user check balance
    b.check_balance()
    a.check_balance()
    c.check_balance()

    #transfer money
    a.send_money('Bob',-10)
    a.send_money('Bob',10)
    b.check_balance()
    a.send_money('Bob',100)
    a.send_money('Alice',100)
    a.send_money('Charlie',10)