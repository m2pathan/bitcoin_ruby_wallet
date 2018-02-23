#Wallet created by: m2pathan
require 'bitcoin'
require 'json'
require './rpc_bitcoinruby.rb'
require 'csv'

#bitcoinRpc object
$bitcoinRpc = BitcoinRPC.new('http://m2pathan:iamjusttestingapplication@127.0.0.1:18332')
Bitcoin.network = :regtest
include Bitcoin::Builder
$BTC = 100000000
$FEE = 1000
FILE_NAME = "keys.csv"

def list_utxo
	res = {}
	if ARGV.length>1
		res = {"error": "Something went wrong!! (listutxo don't have any parameter)"}
	else
		res = get_all_utxo
	end
	return res
end

def generate_key
	res = {}
	if ARGV.length>1
		res = {"error": "Something went wrong!! (generatekey don't have any parameter)"}
	else
		res = generate_key
	end
	return res
end

def list_key
    all_keys = get_all_keys
    return all_keys
end

def send_to_address()	
	res = {}
	if ARGV.length == 5
		txid = ARGV[1]
		vout = ARGV[2]
		amnt = ARGV[3]
		addr = ARGV[4]

		res = validate_input(txid, vout, amnt, addr)
		if res
			#convert amount into satoshi
			amnt = amnt.to_f
			if confirm_send(addr, amnt)
				amnt = amnt * $BTC
				vout = vout.to_i
				addr = addr.to_s
				#sending transaction
				txDetails = $bitcoinRpc.getrawtransaction(txid, true)
				prev_amnt = txDetails["vout"][vout]["value"]
				prev_amnt = prev_amnt * $BTC
				if prev_amnt < (amnt + $FEE)
					return res = {"error" => "in-sufficient balance"} 
				end
				change_amnt = prev_amnt - (amnt + $FEE)
				prev_addr = txDetails["vout"][vout]["scriptPubKey"]["addresses"]	
				response = $bitcoinRpc.gettransaction(txid)
				response = response['hex'].to_s
				prev_tx = Bitcoin::P::Tx.new(response.htb)
				sigKey = get_key(prev_addr[0])
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
					if change_amnt > 0
						t.output do |o|
							o.value change_amnt
							o.script {|s| s.recipient prev_addr[0]}
						end
					end
				end

				res = Bitcoin::Protocol::Tx.new(new_tx.to_payload)
				#p res.verify_input_signature(0, prev_tx) == true
				hex =  res.to_payload.unpack("H*")[0] # hex binary
				
				#sending the raw transaction to network
				transRes = $bitcoinRpc.sendrawtransaction (hex)
				res = {
					"success" => "transaction send successful",
					"txid" => transRes
				}
			end
		end
	else
		res = {
			"error" => "number of parameter mismatch",
			"parameters" => {"1" => "TXID (of the UTXO)", "2" => "Output Index (of the UTXO)", "3" => "Amount", "4" => "Address"}
		}
	end
	return res
end

def send_to_multisig()
	res = {}
	if ARGV.length > 5
		txid = ARGV[1]
		vout = ARGV[2]
		amnt = ARGV[3]
		
		pubKeys = []
		for i in 4..(ARGV.length-1) do
			if (Bitcoin.valid_address? ARGV[i]) && (is_valid_address(ARGV[i]))
				pubKeys << get_key(ARGV[i]).pub
			end
		end

		#validation
		if !is_float? amnt
			return res = {"error" => "invalid amount"}
		end
		if !is_integer? vout	
			return res = {"error" => "invalid vout index"}
		end
		if pubKeys.length <= 0
			return res = {"error" => "invalid addresses"}
		end
		vout = vout.to_i
		if $bitcoinRpc.gettxout(txid, vout) == nil
			return res = {"error" => "invalid transaction id or already spent"}
        end
        if validate_tx_input(txid) == nil
            return res = {"error" => "invalid transaction id or already spent"}
        end

		amnt = amnt.to_f
		amnt = amnt * $BTC
		
		#previous transaction details
		txDetails = $bitcoinRpc.getrawtransaction(txid, true)
		prev_amnt = txDetails["vout"][vout]["value"]
		prev_amnt = prev_amnt * $BTC
		if prev_amnt < (amnt + $FEE)
			return res = {"error" => "in-sufficient balance"} 
		end
		prev_addr = txDetails["vout"][vout]["scriptPubKey"]["addresses"]
		response = $bitcoinRpc.gettransaction(txid)
		response = response['hex'].to_s
		prev_tx = Bitcoin::Protocol::Tx.new(response.htb)
		change_amnt = prev_amnt - (amnt + $FEE)
		key = get_key(prev_addr[0])

		#creating multisig script using public keys
		script_pubkey = Bitcoin::Script.to_multisig_script(2, *pubKeys)
		#p ({ dump_script_pubkey: Bitcoin::Script.new(script_pubkey).to_string })

		#sending amount to multiSig address
		tx = Bitcoin::Protocol::Tx.new
		tx_in = Bitcoin::Protocol::TxIn.from_hex_hash(txid, vout)
		tx.add_in(tx_in)
		tx_out1 = Bitcoin::Protocol::TxOut.new(amnt, script_pubkey)
		tx.add_out(tx_out1)
		if change_amnt>0
			tx_out2 = Bitcoin::Protocol::TxOut.value_to_address(change_amnt, prev_addr[0])
			tx.add_out(tx_out2)
		end

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
		resTxId = $bitcoinRpc.sendrawtransaction(hex)
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

def redeem_to_address()
	res = {}
	if ARGV.length == 5
		txid = ARGV[1]
		vout = ARGV[2]
		amnt = ARGV[3]
		addr = ARGV[4]
		
		#validation
		res = validate_input(txid, vout, amnt, addr)
		if res
			vout = vout.to_i
			amnt = amnt.to_f
            addr = addr.to_s
            amnt = amnt * $BTC
			#previous transaction details
			txDetails = $bitcoinRpc.getrawtransaction(txid, true)
			txType = txDetails["vout"][vout]["scriptPubKey"]["type"]
			if txType != 'multisig'
				return res = {"error" => "input transaction id should be of type multisig"}
			end 
			prev_amnt = txDetails["vout"][vout]["value"]
            prev_amnt = prev_amnt * $BTC
			if prev_amnt < (amnt + $FEE)
				return res = {"error" => "in-sufficient balance"} 
			end
			prev_addrs = txDetails["vout"][vout]["scriptPubKey"]["addresses"]
			response = $bitcoinRpc.gettransaction(txid)
			response = response['hex'].to_s
			prev_tx = Bitcoin::Protocol::Tx.new(response.htb)
			change_amnt = prev_amnt - (amnt + $FEE)
			
			keys = [];
			pubKeys = []
			prev_addrs.each do |pAddr|
				keys << get_key(pAddr)
				pubKeys << get_key(pAddr).pub
			end

			#changes return to multisig address
			script_pubkey = Bitcoin::Script.to_multisig_script(2, *pubKeys)
			#p ({ dump_script_pubkey: Bitcoin::Script.new(script_pubkey).to_string })

			#building new transaction
			tx = Bitcoin::Protocol::Tx.new
			tx_in = Bitcoin::Protocol::TxIn.from_hex_hash(txid, vout)
			tx.add_in(tx_in)
			tx_out1 = Bitcoin::Protocol::TxOut.value_to_address(amnt, addr)
			tx.add_out(tx_out1)
			if change_amnt > 0
				tx_out2 = Bitcoin::Protocol::TxOut.new(change_amnt, script_pubkey)
				tx.add_out(tx_out2)
			end
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
			resTxId = $bitcoinRpc.sendrawtransaction(hex)
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

def validate_input(txid, vout, amnt, addr)	
	if $bitcoinRpc.gettxout(txid, vout.to_i) == nil
		return ({"error" => "transaction id is invalid or already spent"})
	end
	if !Bitcoin.valid_address? addr	
		return ({"error" => "invalid bitcoin address"})
	end
    if !is_valid_address(addr)
        return ({"error" => "invalid bitcoin address"})
    end
    if !is_float? amnt
		return ({"error" => "invalid amount"})
	end
	if !is_integer? vout	
		return ({"error" => "invalid vout index"})
    end
	return true
end

def is_float? string
	true if Float(string) rescue false
end

def is_integer? string
	true if (Integer(string) && string.to_i >=0) rescue false
end

def confirm_send(to, amount)
    $stderr.print "Are you sure you want to send "
    $stderr.print "#{amount} BTC "
    $stderr.print "to \"#{to}\"? (y/n): "
    $stdin.gets.chomp.downcase == 'y'
end

def get_all_utxo
    best_block_hash = $bitcoinRpc.getbestblockhash
    block_details = $bitcoinRpc.getblock best_block_hash
    all_addresses_in_wallet = get_all_addresses
    
    spent_transactions = []
    received_transactions = []
    unspent_transactions = []
  
    # Repeat the process till we do not reach genesis block
    while block_details["previousblockhash"] != nil
        block_details["tx"].each { |trans_id|
        begin
            transaction = $bitcoinRpc.getrawtransaction trans_id, true
            transaction["vin"].each { |vin|
                if vin["txid"] != nil
                    input_transaction = {
                        'trans_id': vin["txid"],
                        'vout_index': vin["vout"]
                    }
                    spent_transactions << input_transaction
                end
            }
            transaction["vout"].each { |vout|
                if vout["scriptPubKey"]["addresses"] != nil
                vout["scriptPubKey"]["addresses"].each { |address|
                    if all_addresses_in_wallet.include? address
                        wallet_transaction = {
                            'trans_id': trans_id,
                            'block_hash': block_details["hash"],
                            'value': vout["value"],
                            'vout_index': vout["n"],
                            'address': vout["scriptPubKey"]["addresses"]
                        }
                        received_transactions << wallet_transaction
                        break
                    end
                }
                end
            }
            rescue => ex
        end
    }
    block_details = $bitcoinRpc.getblock block_details["previousblockhash"]
    end
  
    received_transactions.each { |trans|
        unless spent_transactions.any? { |tx| tx[:trans_id] == trans[:trans_id] and tx[:vout_index] == trans[:vout_index] }
            unspent_transactions << trans
        end
    }
    unspent_transactions
end

def validate_tx_input (txid)
    all_utxo = get_all_utxo
    transaction = nil
    all_utxo.each { |utxo|
        if utxo[:trans_id] == txid
            transaction = utxo
        end
    }
    transaction
end

def generate_key
    key = Bitcoin::Key.generate
    key_info = [key.addr, key.pub, key.to_base58]
    $bitcoinRpc.importprivkey key.to_base58
    CSV.open(FILE_NAME, "a+") do |csv|
        csv << key_info
    end
    res = {
        "Address" => key.addr,
        "PubKey" => key.pub
	}
    res
end

def get_all_keys
    response = []
    CSV.foreach(FILE_NAME) do |row|
        key = {
            'address' => row[0],
            'pubkey' => row[1],
            'privkey' => row[2]
        }
        response << key
    end
    response
end

def get_all_addresses
    response = []
    CSV.foreach(FILE_NAME) do |row|
        response << row[0]
    end
    response
end

def get_private_key ( address )
    private_key = nil
    CSV.foreach(FILE_NAME) do |row|
        if address == row[0]
            private_key = row[2]
            break
        end
    end
    private_key
end

def get_key ( address )
    privkey = get_private_key address
    key = Bitcoin::Key.from_base58 ( privkey )
    key
end

def is_valid_address ( address )
    all_addresses = get_all_addresses
    all_addresses.include? address
end

if ARGV.length > 0
	@command = ARGV[0]
	case @command
		when "listutxo"
			res = list_utxo()
			puts JSON.pretty_generate(res)
		when "generatekey"
			res = generate_key()
			puts JSON.pretty_generate(res)
		when "listkey"
            res = list_key()
			puts JSON.pretty_generate(res)
		when "sendtoaddress"
			res = send_to_address()
			puts JSON.pretty_generate(res)
		when "sendtomultisig"
			res = send_to_multisig()
			puts JSON.pretty_generate(res)
		when "redeemtoaddress"
			res = redeem_to_address()
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
			puts "Command not found!!! (Type 'ruby wallet.rb help' for list of commands supported)"
	end #end of case
else
	puts "Need help? Type 'ruby wallet.rb help'"
end
