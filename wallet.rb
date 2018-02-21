#Wallet created by: m2pathan
require 'bitcoin'
require 'json'
require './rpc_bitcoinruby.rb'
require 'csv'

#rpc object
@rpc = BitcoinRPC.new('http://m2pathan:iamjusttestingapplication@127.0.0.1:18332')
Bitcoin.network = :regtest
include Bitcoin::Builder
$BTC = 100000000
$FEE = 1000

def listutxo
	res = {}
	if ARGV.length>1
		res = {"error": "Something went wrong!! (listutxo don't have any parameter)"}
	else
		bestBlockHash = @rpc.getbestblockhash()
		block = @rpc.getblock(bestBlockHash)
		txList = block["tx"]
		txList.each do |tx|
			txDetails = @rpc.getrawtransaction(tx, true)
			vCount = 0;
			txDetails["vout"].each do |txD| 
				if txD["scriptPubKey"]["type"] != "nulldata"
					res = {
						"txid" => tx,
						"Address" => txD["scriptPubKey"]["addresses"],
						"Amount" => txD["value"],
						"Vout index" => vCount
					}
				end #if close
				vCount = vCount +1
			end #do close
			puts "---------------------------------------------------"
		end #do close
	end #else close
	return res
end

def generatekey
	res = {}
	if ARGV.length>1
		res = {"error": "Something went wrong!! (generatekey don't have any parameter)"}
	else
		key = Bitcoin::Key.generate(opts = { compressed: false })
		res = {
			"Address" => key.addr,
			"PubKey" => key.pub
		}
		@rpc.importprivkey(key.to_base58)
		CSV.open("keys.csv", "a") do |csv|
			csv << [key.addr, key.pub, key.priv]
		end #csv close
	end #else close
	return res
end

def listkey
	if File.file?( "keys.csv" )
		CSV.foreach("keys.csv") do |row|
			res = {
				"Address" => row[0],
				"PubKey" => row[1],
				"PrivKey" => row[2]
			}
			puts JSON.pretty_generate(res)
		end #csv close
	else
		puts "error": "Unable to read keys"
	end #else close
end

def sendtoaddress()	
	res = {}
	if ARGV.length == 5
		txid = ARGV[1]
		vout = ARGV[2]
		amnt = ARGV[3]
		addr = ARGV[4]
		
		#TODO: validate the parameters
		res = validateInput(txid, vout, amnt, addr)
		if res == {}
			#convert amount into satoshi
			amnt = amnt.to_f
			amnt = amnt * $BTC
			
			#sending transaction
			txDetails = @rpc.getrawtransaction(txid, true)
			prev_amnt = txDetails["vout"][vout]["value"]
			prev_amnt = prev_amnt * $BTC
			if prev_amnt < (amnt + $FEE)
				res = {"error" => "in-sufficient balance"} 
			end
			change_amnt = prev_amnt - (amnt + $FEE)
			prev_addr = txDetails["vout"][vout]["scriptPubKey"]["addresses"]	
			response = @rpc.gettransaction(txid)
			response = response['hex'].to_s
			$prev_tx = Bitcoin::P::Tx.new(response.htb)
			prev_tx = $prev_tx
			sigKey = Bitcoin::Key.from_base58(@rpc.dumpprivkey(prev_addr[0]))
			new_tx = build_tx do |t|
				t.input do |i|
					i.prev_out prev_tx
					i.prev_out_index vout
					i.signature_key sigKey
				end
				t.output do |o|
					o.value amnt
					o.script {|s| s.recipient addr}
				end
				t.output do |o|
					o.value change_amnt
					o.script {|s| s.recipient prev_addr[0]}
				end
			end

			res = Bitcoin::Protocol::Tx.new(new_tx.to_payload)
			#p res.verify_input_signature(0, prev_tx) == true
			hex =  res.to_payload.unpack("H*")[0] # hex binary
			
			#sending the raw transaction to network
			transRes = @rpc.sendrawtransaction (hex)
			res = {
				"success" => "transaction send successful",
				"txid" => transRes
			}
		end
	else
		res = {
			"error" => "number of parameter mismatch",
			"parameters" => {"1" => "TXID (of the UTXO)", "2" => "Output Index (of the UTXO)", "3" => "Amount", "4" => "Address"}
		}
	end
	return res
end

def sendtomultisig()
	res = {}
	if ARGV.length > 5
		txid = ARGV[1]
		vout = ARGV[2]
		amnt = ARGV[3]
		amnt = amnt * $BTC
		pubKeys = []
		for i in 4..(ARGV.length-1) do
			if Bitcoin.valid_address? ARGV[i]
				pubKeys << Bitcoin::Key.from_base58(@rpc.dumpprivkey(ARGV[i])).pub
			end
		end

		#TODO: validation
		if !is_float? amnt
			return res = {"error" => "invalid amount"}
		end
		if !is_integer? vout	
			return res = {"error" => "invalid vout index"}
		end
		if pubKeys.length <= 0
			return res = {"error" => "invalid addresses"}
		end

		#previous transaction details
		txDetails = @rpc.getrawtransaction(txid, true)
		prev_amnt = txDetails["vout"][vout]["value"]
		prev_amnt = prev_amnt * $BTC
		if prev_amnt < (amnt + $FEE)
			return res = {"error" => "in-sufficient balance"} 
		end
		prev_addr = txDetails["vout"][vout]["scriptPubKey"]["addresses"]
		response = @rpc.gettransaction(txid)
		response = response['hex'].to_s
		prev_tx = Bitcoin::Protocol::Tx.new(response.htb)
		change_amnt = prev_amnt - (amnt + $FEE)
		key = Bitcoin::Key.from_base58(@rpc.dumpprivkey(prev_addr[0]))

		#creating multisig script using public keys
		script_pubkey = Bitcoin::Script.to_multisig_script(2, *pubKeys)
		#p ({ dump_script_pubkey: Bitcoin::Script.new(script_pubkey).to_string })

		#sending amount to multiSig address
		tx = Bitcoin::Protocol::Tx.new
		tx_in = Bitcoin::Protocol::TxIn.from_hex_hash(txid, vout)
		tx.add_in(tx_in)
		tx_out1 = Bitcoin::Protocol::TxOut.new(amnt, script_pubkey)
		tx_out2 = Bitcoin::Protocol::TxOut.new(change_amnt, prev_addr[0])
		tx.add_out(tx_out1)
		tx.add_out(tx_out2)

		#add signature to the new transaction
		sig_hash = tx.signature_hash_for_input(0, prev_tx, Bitcoin::Script::SIGHASH_TYPE[:all])
		signature = key.sign(sig_hash)
		script_sig = Bitcoin::Script.to_signature_pubkey_script(signature, key.pub.htb, Bitcoin::Script::SIGHASH_TYPE[:all])
		tx.in[0].script_sig = script_sig

		#verify the signature
		verify_tx = Bitcoin::Protocol::Tx.new(tx.to_payload)
		#p ({ verify: verify_tx.verify_input_signature(0, prev_tx) })

		#sending transaction on network using BitcoinRPC
		hex =  verify_tx.to_payload.unpack("H*")[0] # hex binary
		#puts hex.to_s
		resTxId = @rpc.sendrawtransaction(hex)
		res = {
			"success" => "transaction send successful",
			"txid" => resTxId
		}
	else
		res = {
			"error" => "number of parameter mismatch",
			"parameters" => {"1" => "TXID (of the UTXO)", "2" => "Output Index (of the UTXO)", "3" => "Amount", "4" => "Addresses (2, 3 .. n)"}
		}
	end
end

def redeemtoaddress()
	res = {}
	if ARGV.length == 5
		txid = ARGV[1]
		vout = ARGV[2]
		amnt = ARGV[3]
		addr = ARGV[4]
		amnt = amnt * $BTC

		#TODO: validation
		res = validateInput(txid, vout, amnt, addr)
		if res == {}
			vout = vout.to_i
			amnt = amnt.to_f
			addr = addr.to_s
			#previous transaction details
			txDetails = @rpc.getrawtransaction(txid, true)
			prev_amnt = txDetails["vout"][vout]["value"]
			prev_amnt = prev_amnt * $BTC
			if prev_amnt < (amnt + $FEE)
				return res = {"error" => "in-sufficient balance"} 
			end
			prev_addrs = txDetails["vout"][vout]["scriptPubKey"]["addresses"]
			response = @rpc.gettransaction(txid)
			response = response['hex'].to_s
			prev_tx = Bitcoin::Protocol::Tx.new(response.htb)
			change_amnt = prev_amnt - (amnt + $FEE)
			
			keys = [];
			pubKeys = []
			prev_addrs.each do |pAddr|
				keys << Bitcoin::Key.from_base58(@rpc.dumpprivkey(pAddr))
				pubKeys << Bitcoin::Key.from_base58(@rpc.dumpprivkey(pAddr)).pub
			end

			#changes return to multisig address
			script_pubkey = Bitcoin::Script.to_multisig_script(2, *pubKeys)
			#p ({ dump_script_pubkey: Bitcoin::Script.new(script_pubkey).to_string })

			#building new transaction
			tx = Bitcoin::Protocol::Tx.new
			tx_in = Bitcoin::Protocol::TxIn.from_hex_hash(txid, vout)
			tx.add_in(tx_in)
			tx_out1 = Bitcoin::Protocol::TxOut.value_to_address(amnt, addr)
			tx_out2 = Bitcoin::Protocol::TxOut.new(change_amnt, script_pubkey)
			tx.add_out(tx_out1)
			tx.add_out(tx_out2)

			sig_hash = tx.signature_hash_for_input(0, prev_tx, Bitcoin::Script::SIGHASH_TYPE[:all])

			#signing the transaction
			#script_sig = Bitcoin::Script.to_multisig_script_sig(key1.sign(sig_hash), key2.sign(sig_hash), key3.sign(sig_hash))
			#script_sig = Bitcoin::Script.add_sig_to_multisig_script_sig(key1.sign(sig_hash), script_sig)
			#script_sig = Bitcoin::Script.add_sig_to_multisig_script_sig(key2.sign(sig_hash), script_sig)
			#script_sig = Bitcoin::Script.add_sig_to_multisig_script_sig(key3.sign(sig_hash), script_sig)
			script_sig = Bitcoin::Script.to_multisig_script_sig(keys[0].sign(sig_hash), keys[1].sign(sig_hash))
			# counter = keys.length;
			# script_sig = Bitcoin::Script.to_multisig_script_sig(keys[0].sign(sig_hash))
			# keys.reverse.each do |subKey|
			# 	if counter != 0 
			# 		script_sig = Bitcoin::Script.add_sig_to_multisig_script_sig(subKey.sign(sig_hash), script_sig)
			# 	end
			# 	counter = counter - 1
			# end

			tx.in[0].script_sig = script_sig

			#verify the transaction signature
			verify_tx = Bitcoin::Protocol::Tx.new(tx.to_payload)
			#p ({verify: verify_tx.verify_input_signature(0, prev_tx)})

			#sending transaction on network using BitcoinRPC
			hex =  verify_tx.to_payload.unpack("H*")[0] # hex binary
			#puts hex.to_s
			resTxId = @rpc.sendrawtransaction(hex)
			res = {
				"success" => "transaction send successful",
				"txid" => resTxId
			}
		else
		end
	else
		res = {
			"error" => "number of parameter mismatch",
			"parameters" => {"1" => "TXID (of the UTXO)", "2" => "Output Index (of the UTXO)", "3" => "Amount", "4" => "Address"}
		}
	end
	return res
end

def validateInput(txid, vout, amnt, addr)	
	if !Bitcoin.valid_address? addr	
		return ({"error" => "invalid bitcoin address"})
	end
	if !is_float? amnt
		return ({"error" => "invalid amount"})
	end
	if !is_integer? vout	
		return ({"error" => "invalid vout index"})
	end
	return {}
end

def is_float? string
	true if Float(string) rescue false
end

def is_integer? string
	true if (Integer(string) && string.to_i >=0) rescue false
end

if ARGV.length > 0
    @command = ARGV[0]
	case @command
		when "listutxo"
			res = listutxo()
			puts JSON.pretty_generate(res)
		when "generatekey"
			res = generatekey()
			puts JSON.pretty_generate(res)
		when "listkey"
			listkey()
		when "sendtoaddress"
			res = sendtoaddress()
			puts JSON.pretty_generate(res)
		when "sendtomultisig"
			res = sendtomultisig()
			puts JSON.pretty_generate(res)
		when "redeemtoaddress"
			res = redeemtoaddress()
			puts JSON.pretty_generate(res)
		when "help"
			puts "======================================================================"
	  		puts "1. listutxo  -  List the all UTXO in the longest blockchain."
			puts "2. generatekey  -  Generate new secret key and returns the corresponding Public Key and Address."
			puts "3. listkey  -  List all the generated keys"
			puts "4. sendtoaddress  -  Send indicated value from your own UTXO to other address"
			puts "5. sendtomultisig  -  Send indicated value from your own UTXO to mulisig"
			puts "6. redeemtoaddress  -  Send indicated value from your own UTXO from mulisig"
			puts "======================================================================"
		else
			"Command not found!!! (Type 'ruby wallet.rb help' for list of commands supported)"
	end #end of case
else
	puts "Need help? Type 'ruby wallet.rb help'"
end
