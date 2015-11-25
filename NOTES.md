
# High Level Application flow

* User requests public key from server (prepare multisig)

* User requests blockchain endpoint (commit multisig - we know the redeem script)

* User pays funds via blockchain to P2SH (or opens a payment channel etc.)

	* Inputs: any
	* Output: P2SH of multisig (or whatever contract is required)
	* Output: OP_RETURN
		* sha256(code or package hash) - MUST be 1st
		* zero or more sha256(data)

* User waits for protocol/validator-required number of confirmations

* User calls ora API /exec

# API /exec Execution Flow

* ora reads transaction from blockchain (chain, txid)

* ora builds list of code+data hashes.  The first hash MUST refer to
  either sha256(32-bit LE moxie ELF binary) or sha256(ora package)

* if nonce provided,
	* verify len(input hash list) == len(op return hash list)
	* replace list with input_hashes list
	* for each hash in replacement list, verify
		sha256(salt + new_list[i]) == old_list[i]

* download first hash from filenet

* if first data is an ora package, process ora package,
  possibly adding additional hashes to hash list.

* download remaining hashes from filenet

* load code and data into sandbox

* execute sandbox

* gather & hash insn count, ret code and output data

* return output to user



# API reference

## API /new.key

### Input

	URI: GET /new.key
	chain=[bitcoin, testnet3, ...]

### Output

	key id (== public key hash aka address)
	Newly generated public key

## API /new.multisig

### Input

	URI: GET /new.multisig
	key_id=<chain-specific public key hash from /new.key>
	redeem_script=<p2sh redeem script - must include our public key>

### Output

	p2sh address, if successful

## API /monitor

### Input

	URI: GET /monitor
	address=p2sh address to monitor
	input_hashes=[if salted, REQUIRED list of input
		      code+data hashes, to be triggered upon
		      sufficient P2SH spend]
	input_data=[zero or more input bytestreams, to
		    pre-warm caches and eliminate backend
		    storage round-trips]

	Implicit process input: block headers, input transaction

### Output

## API /exec

### Input
	URI: POST /exec
	chain=[bitcoin, testnet3, ...]
	txid=<chain txid>
	salt=<optional salt, used in building OP_RET, above]
	input_hashes=[if salted, REQUIRED list of input
		      code+data hashes]
	input_data=[zero or more input bytestreams, to
		    pre-warm caches and eliminate backend
		    storage round-trips]

### Output
	le64 instruction count
	le32 return code
	output buffer, 0-16,000,000 bytes in size
	sha256(le64 insn_count + le32 return_code + output)

## API /sign

### Input
	URI: POST /sign
	chain=[bitcoin, testnet3, ...]
	txid=<chain txid>
	salt=<optional salt, used in building OP_RET, above]
	input_hashes=[if salted, REQUIRED list of input
		      code+data hashes]
	input_data=[zero or more input bytestreams, to
		    pre-warm caches and eliminate backend
		    storage round-trips]

	tx=<hex encoded transaction>
	contract_id=<public key hash of key to sign this tx>

### Output, if return code == 0

	signed transaction

### Output, if return code != 0

	le64 instruction count
	le32 return code
	output buffer, 0-16,000,000 bytes in size
	sha256(le64 insn_count + le32 return_code + output)

