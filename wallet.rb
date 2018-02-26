# Wallet created by: m2pathan
require 'bitcoin'
require 'json'
require './rpc_bitcoinruby.rb'
require 'csv'

# BTC_RPC object
$BTC_RPC = BitcoinRPC.new('http://m2pathan:iamjusttestingapplication@127.0.0.1:18332')
Bitcoin.network = :regtest
include Bitcoin::Builder
$BTC = 100000000
$FEE = 1000
FILE_NAME = "keys.csv"

# Class which manages all keys related operations
class Key

  def generate_key
    key = Bitcoin::Key.generate
    key_info = [key.addr, key.pub, key.to_base58]
    $BTC_RPC.importprivkey key.to_base58
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
  
  def get_private_key(addr)
    private_key = nil
    CSV.foreach(FILE_NAME) do |row|
      if addr == row[0]
        private_key = row[2]
        break
      end
    end
    private_key
  end
  
  def get_key(addr)
    privkey = get_private_key addr
    key = Bitcoin::Key.from_base58(privkey)
    key
  end
  
  def is_valid_address(addr)
    all_addresses = get_all_addresses
    all_addresses.include? addr
  end

end

# Class which manages all transactions
class Transaction

  def initialize
    @key = Key.new
  end

  def get_all_utxo
    best_block_hash = $BTC_RPC.getbestblockhash
    block_details = $BTC_RPC.getblock best_block_hash
    all_addresses_in_wallet = @key.get_all_addresses
    spent_transactions = []
    received_transactions = []
    unspent_transactions = []
  
    # Repeat the process till we do not reach genesis block
    while block_details["previousblockhash"] != nil
      block_details["tx"].each { |trans_id|
        begin
          transaction = $BTC_RPC.getrawtransaction trans_id, true
          transaction["vin"].each { |vin|
            if vin["txid"] != nil
              input_transaction = {
                  'trans_id' => vin["txid"],
                  'vout_index' => vin["vout"]
              }
              spent_transactions << input_transaction
            end
          }
          transaction["vout"].each { |vout|
            if vout["scriptPubKey"]["addresses"] != nil
              vout["scriptPubKey"]["addresses"].each { |address|
                if all_addresses_in_wallet.include? address
                  wallet_transaction = {
                      'trans_id' => trans_id,
                      'block_hash' => block_details["hash"],
                      'value' => vout["value"],
                      'vout_index' => vout["n"],
                      'address' => vout["scriptPubKey"]["addresses"]
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
      block_details = $BTC_RPC.getblock block_details["previousblockhash"]
    end
  
    received_transactions.each { |trans|
      unless spent_transactions.any? { |tx| tx["trans_id"] == trans["trans_id"] and tx["vout_index"] == trans["vout_index"] }
        unspent_transactions << trans
      end
    }
    unspent_transactions
  end
  
  def validate_tx_input(txid, vout)
    all_utxo = get_all_utxo
    transaction = nil
    all_utxo.each { |utxo|
      if (utxo["trans_id"] == txid) && (utxo["vout_index"] == vout)
        transaction = utxo
      end
    }
    transaction
  end

end

# Class which manages all utility related operations
class Util

  def initialize
    @key = Key.new
    @transaction = Transaction.new
  end

  def validate_input(txid, vout, amnt, addr)	
    if !is_integer? vout	
      return ({"error" => "invalid vout index"})
    end
    if $BTC_RPC.gettxout(txid, vout.to_i) == nil
      return ({"error" => "transaction id is invalid or already spent"})
    end
    if @transaction.validate_tx_input(txid, vout.to_i) == nil
      return ({"error" => "invalid transaction id or already spent"})
    end
    if !Bitcoin.valid_address? addr	
      return ({"error" => "invalid bitcoin address"})
    end
    if !@key.is_valid_address(addr)
      return ({"error" => "invalid bitcoin address"})
    end
    if !is_float? amnt
      return ({"error" => "invalid amount"})
    end
    return true
  end
  
  def is_float? string
    true if Float(string) rescue false
  end
  
  def is_integer? string
    true if (Integer(string) && string.to_i >= 0) rescue false
  end
  
  def confirm_send(to, amount)
    $stderr.print "Are you sure you want to send "
    $stderr.print "#{amount} BTC "
    $stderr.print "to \"#{to}\"? (y/n): "
    $stdin.gets.chomp.downcase == 'y'
  end

end

# Class which manages all wallet related operations
class Wallet

  def initialize
    @transaction = Transaction.new
    @key = Key.new
    @util = Util.new
  end

  def list_utxo
    res = {}
    if ARGV.length > 1
      res = { "error" => "Something went wrong!! (listutxo don't have any parameter)" }
    else
      res = @transaction.get_all_utxo
    end
    return res
  end
  
  def generate_key
    res = {}
    if ARGV.length > 1
      res = { "error" => "Something went wrong!! (generatekey don't have any parameter)" }
    else
      res = @key.generate_key
    end
    return res
  end
  
  def list_key
    return @key.get_all_keys
  end
  
  def send_to_address
    res = {}
    if ARGV.length == 5
      txid = ARGV[1]
      vout = ARGV[2]
      amnt = ARGV[3]
      addr = ARGV[4]
  
      res = @util.validate_input(txid, vout, amnt, addr)
      if res == true
        #convert amount into satoshi
        amnt = amnt.to_f
        if @util.confirm_send(addr, amnt)
          amnt = amnt * $BTC
          vout = vout.to_i
          addr = addr.to_s
          #sending transaction
          tx_details = $BTC_RPC.getrawtransaction(txid, true)
          prev_amnt = tx_details["vout"][vout]["value"]
          prev_amnt = prev_amnt * $BTC
          if prev_amnt < (amnt + $FEE)
            return res = {"error" => "in-sufficient balance"} 
          end
          change_amnt = prev_amnt - (amnt + $FEE)
          prev_addr = tx_details["vout"][vout]["scriptPubKey"]["addresses"]	
          response = $BTC_RPC.gettransaction(txid)
          response = response['hex'].to_s
          prev_tx = Bitcoin::P::Tx.new(response.htb)
          sig_key = @key.get_key(prev_addr[0])
          new_tx = build_tx do |t|
            t.input do |i|
              i.prev_out prev_tx
              i.prev_out_index vout
              i.signature_key sig_key
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
          trans_res = $BTC_RPC.sendrawtransaction(hex)
          res = {
            "success" => "transaction send successful",
            "txid" => trans_res
          }
        end
      end
    else
      res = {
        "error" => "number of parameter mismatch",
        "parameters" => {
          "1" => "TXID (of the UTXO)", 
          "2" => "Output Index (of the UTXO)", 
          "3" => "Amount", 
          "4" => "Address"
        }
      }
    end
    return res
  end
  
  def send_to_multisig
    res = {}
    if ARGV.length > 5
      txid = ARGV[1]
      vout = ARGV[2]
      amnt = ARGV[3]
      
      pubkeys = []
      for i in 4..(ARGV.length-1) do
        if (Bitcoin.valid_address? ARGV[i]) && (@key.is_valid_address(ARGV[i]))
          pubkeys << @key.get_key(ARGV[i]).pub
        end
      end
  
      #validation
      if !@util.is_float? amnt
        return ({"error" => "invalid amount"})
      end
      if !@util.is_integer? vout	
        return ({"error" => "invalid vout index"})
      end
      if pubkeys.length <= 0
        return ({"error" => "invalid addresses"})
      end
      vout = vout.to_i
      if $BTC_RPC.gettxout(txid, vout) == nil
        return ({"error" => "invalid transaction id or already spent"})
      end
      if @transaction.validate_tx_input(txid, vout) == nil
        return ({"error" => "invalid transaction id or already spent"})
      end
  
      amnt = amnt.to_f
      amnt = amnt * $BTC
      
      #previous transaction details
      txDetails = $BTC_RPC.getrawtransaction(txid, true)
      prev_amnt = txDetails["vout"][vout]["value"]
      prev_amnt = prev_amnt * $BTC
      if prev_amnt < (amnt + $FEE)
        return ({"error" => "in-sufficient balance"})
      end
      prev_addr = txDetails["vout"][vout]["scriptPubKey"]["addresses"]
      response = $BTC_RPC.gettransaction(txid)
      response = response['hex'].to_s
      prev_tx = Bitcoin::Protocol::Tx.new(response.htb)
      change_amnt = prev_amnt - (amnt + $FEE)
      key = @key.get_key(prev_addr[0])
  
      #creating multisig script using public keys
      script_pubkey = Bitcoin::Script.to_multisig_script(2, *pubkeys)
      #p ({ dump_script_pubkey: Bitcoin::Script.new(script_pubkey).to_string })
  
      #sending amount to multiSig address
      tx = Bitcoin::Protocol::Tx.new
      tx_in = Bitcoin::Protocol::TxIn.from_hex_hash(txid, vout)
      tx.add_in(tx_in)
      tx_out1 = Bitcoin::Protocol::TxOut.new(amnt, script_pubkey)
      tx.add_out(tx_out1)
      if change_amnt > 0
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
      trans_res = $BTC_RPC.sendrawtransaction(hex)
      res = {
        "success" => "transaction send successful",
        "txid" => trans_res
      }
    else
      res = {
        "error" => "number of parameter mismatch",
        "parameters" => {
          "1" => "TXID (of the UTXO)",
          "2" => "Output Index (of the UTXO)",
          "3" => "Amount",
          "4" => "Addresses (2, 3 .. n)"
        }
      }
    end
  end
  
  def redeem_to_address
    res = {}
    if ARGV.length == 5
      txid = ARGV[1]
      vout = ARGV[2]
      amnt = ARGV[3]
      addr = ARGV[4]
      
      #validation
      res = @util.validate_input(txid, vout, amnt, addr)
      if res == true
        vout = vout.to_i
        amnt = amnt.to_f
        addr = addr.to_s
        amnt = amnt * $BTC
        #previous transaction details
        tx_details = $BTC_RPC.getrawtransaction(txid, true)
        txType = tx_details["vout"][vout]["scriptPubKey"]["type"]
        
        if txType != 'multisig'
          return ({"error" => "input transaction id should be of type multisig"})
        end 
        
        prev_amnt = tx_details["vout"][vout]["value"]
        prev_amnt = prev_amnt * $BTC
  
        if prev_amnt < (amnt + $FEE)
          return ({"error" => "in-sufficient balance"})
        end
        
        prev_addrs = tx_details["vout"][vout]["scriptPubKey"]["addresses"]
        response = $BTC_RPC.gettransaction(txid)
        response = response['hex'].to_s
        prev_tx = Bitcoin::Protocol::Tx.new(response.htb)
        change_amnt = prev_amnt - (amnt + $FEE)
        
        keys = [];
        pubKeys = []
        
        prev_addrs.each do |pAddr|
          keys << @key.get_key(pAddr)
          pubKeys << @key.get_key(pAddr).pub
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
        script_sig = Bitcoin::Script.to_multisig_script_sig(keys[0].sign(sig_hash), keys[1].sign(sig_hash))
        
        tx.in[0].script_sig = script_sig
  
        #verify the transaction signature
        verify_tx = Bitcoin::Protocol::Tx.new(tx.to_payload)
        #p ({verify: verify_tx.verify_input_signature(0, prev_tx)})
  
        #sending transaction on network using BitcoinRPC
        hex =  verify_tx.to_payload.unpack("H*")[0] # hex binary
        #puts hex.to_s
        trans_res = $BTC_RPC.sendrawtransaction(hex)
        res = {
          "success" => "transaction send successful",
          "txid" => trans_res
        }
      end
    else
      res = {
        "error" => "number of parameter mismatch",
        "parameters" => {
          "1" => "TXID (of the UTXO)",
          "2" => "Output Index (of the UTXO)",
          "3" => "Amount",
          "4" => "Address"
        }
      }
    end
    return res
  end

end

if ARGV.length > 0
  @command = ARGV[0]
  @wallet = Wallet.new
	case @command
  when "listutxo"
    res = @wallet.list_utxo
    puts JSON.pretty_generate(res)
  when "generatekey"
    res = @wallet.generate_key
    puts JSON.pretty_generate(res)
  when "listkey"
    res = @wallet.list_key
    puts JSON.pretty_generate(res)
  when "sendtoaddress"
    res = @wallet.send_to_address
    puts JSON.pretty_generate(res)
  when "sendtomultisig"
    res = @wallet.send_to_multisig
    puts JSON.pretty_generate(res)
  when "redeemtoaddress"
    res = @wallet.redeem_to_address
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