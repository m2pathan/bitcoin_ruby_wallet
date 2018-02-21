# Simple Wallet using Ruby

Very simple wallet using Ruby language and `bitcoin-ruby`.

## Commands Supported

A usage of this wallet is as follows.

``` bash
ruby wallet.rb <command>[ <arg 1> <arg 2> ... <arg n>]
```

### 1. listutxo

* List the all UTXO in the longest blockchain which is pointed in   `getbestblockhash`
* Shows the following information of each UTXO
  * Outpoint (Block hash and TXID and output index)
  * Amount
  * Corresponding Address(or Public key)

### 2. generatekey

* Generate new ESDSA secret key and store it to a `keys.csv` file
* Show corresponding Public key and Address when successfully generated  

### 3. listkey

* List the all generated keys which is stored in `keys.csv`
* Show the following information of each key
  * Private key
  * Public key 
  * Address

### 4. sendtoaddress

* Send indicated value from your own UTXO to other address 
* Arguments of the command are as follows
  * TXID (of the UTXO)
  * Output Index (of the UTXO)
  * Amount
  * Address
* Changes are sent again to the original address

### 5. sendtomultisig

* Send indicated value from your own UTXO to mulisig  
* Arguments of the command are as follows
  * TXID (of the UTXO)
  * Output Index (of the UTXO)
  * Amount
  * Address 1, 2 .. n
* Changes are sent again to the original address

### 6. redeemtoaddress

* Send indicated value from your own UTXO from mulisig  
* Arguments of the command are as follows
  * TXID (of the UTXO)
  * Output Index (of the UTXO)
  * Amount
  * Address
* Changes are sent again to the original multi sig
