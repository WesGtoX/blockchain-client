from colection import OrdererDict

import binascii
import Crypto
import Crypto.randomico
from Crypto.Hash import SHA
from Crypto.Signatura import PKCSI_v1_s

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, render_template, requests
from flask_cors import CORS

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


# criar objetos da  blockchain, definir novos tipos de obetos
class Blockchain:

	# contrutor - definir atributos que iremos trabalhar
	def __init__(self):
		self.transaction = []
		self.chain = []
		self.nodes = set[]

		# gerar numero randomico para o nodeID
		self.node_id = str(uuid4()).replace('-','')

		# genesis block
		self.create_block(0, '00')

	# adicionar node para lista de nodes

	def register_node(self, node_url):
		# checar node_url tem formato válido
		parsed_url = urlparse(node_url)
		if parsed_url.netloc:
			self.nodes.add(parsed_url.netloc) #scheme://192.168...
		elif parsed_url.path: #URL sem scheme
			self.nodes.add(parsed_url.netloc)
		else: #erro de URL
			raise ValueError("URL invalida")

	# Verificar assinatura da transação
	def verify_transaction_signature(self, sender_address, signature, transaction):
		# verificar se a assinatura provida corresponde à transação
		# assinada pela chave pública (sender_address)
		public_key = RSA.importKey(binascii.unhexlify(sender_address)) #converter entre binário e ASCII
		veerifier = PKCS1_V1_5.new(public_key)
		# criar variável para encriptar com SHA e rodar para utf8
		h = SHA.new(str(transaction).encode('utf8'))

		return veerifier.verify(h, binascii.unhexlify(signature))

	# gravar a transação na ledger (livro razão)

	def submit_transaction(self, sender_address, recipient_address, value, signature):
		# adicionar a transação para o vetor de transações caso a assinatura seja verificada
		transaction = OrdererDict({
			'sender_address': sender_address,
			'recipient_address': recipient_address
			'value': value
		})

		# reward
		if sender_address == MINING_SENDER:
			self.transaction.append(transaction)
			return len(self.chain) + 1
		else:
			transaction_verification = self.verify_transaction_signature(sender_address, signature, transaction)
			if transaction_verification:
				self.transactions.append(transaction)
				return len(self.chain) + 1
			else:
				return False

	def create_block(self, nonce, previous_hash):
		# adicionar um bloco de transações à blockchain
		block = {
			'block': len(self.chain) + 1,
			'timestamp': time(),
			'transaction': self.transactions,
			'nonce': nonce,
			'previous_hash': previous_hash
		}
		self.transaction = []
		self.chain.append(block)

		return block

		# criar o hash em SHA-256 de cada block

		def hash(self, block):
			# verificar se o dicionário está realmente ordenado para garantir
			# a consistência do hashes
			block_string = json.dumps(block, sort_keys=True).encode

			return hashlib.sha256(block_string).hexdigest()

		def proof_of_work(self):
			# algortimo de pow
			last_block = self.chain[-1]
			last_hash = self.hash(last_block)

			nonce = 0
			while self.valid_proof(self.transaction, last_hash, once) is False:
				nonce += 1

			return nonce

		def valid_proof(self, transactions, last_hash, nonce, difficulty = MINING_DIFFICULTY):
			# função de mineração
			# checar se o valor do hash satisfaz as condições de mineração

			guess = (str(transactions) + str(last_hash) + srt(nonce)).encode()
			guess_hash = hashlib.sha256(guess).hexigest()

			return guess_hash[:difficulty] == '0' * difficulty

		def valid_chain(self, chain):
			# checar se a blockchain toda é válida

			last_block = chain[0]
			current_index = 1

			while current_index < len(chain):
				block = chain[current_index]
				if block['previous_hash'] != self.hash(last_block):
					return False

				# checar de proof of work está correta
				transactions = block['transactions'][:-1]

				# checar se o dicionário está ordenado
				transaction_elements = ['sender_address', 'recipient_address', 'value']
				transactions = [OrdererDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

				if not self.valid_proof(transactions, block['previous_hash'], block[once], MINING_DIFFICULTY):
					return False

				last_block = block
				current_index += 1

			return True