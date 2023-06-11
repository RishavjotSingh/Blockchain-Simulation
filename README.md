# Blockchain-Simulation

- Developed a robust Proof-of-Work (PoW) blockchain simulation, leveraging SHA-256 cryptographic hashing and nonce discovery for secure block mining.
- Implemented PoW consensus mechanism to ensure transaction validity and order agreement among participants, ensuring a reliable and secure blockchain network.
- Implemented peer-to-peer network communication to maintain synchronization and facilitate consensus among the miners.

## How to run
After cloning or copy-pasting the code from the Python file, use this command in Terminal/Command Prompt to run the code:
```python blockchain_simulation.py```

## Important Information
- I use two ports: hostPort = 8306 and announceBlockHostPort = 8308.
- announcedBlocksPort is the port which I use to announce the block that I mine. Actually, I make a new socket whenever I mine a block to announce that block, so this new announcedBlocksPort is required because hostPort is already in use at that time. 
- So, please make sure that both of these ports are not in use when you run the code. If announceBlockHostPort is in use then the socket will not bind. So, please check this before running.
- Another important thing is that if the peer is doing other operation like Consensus, then it replies with appropriate reply-type and hash = "Busy doing some other operation right now."
- Clean up peers that have not sent FLOOD messages: There is a function checkPeersWhoSentFloods() which is called every 60 seconds. Whenever, a FLOOD message is received, that peer's details (host, port) are stored in a list (receivedFloodsFromPeers). If any of the current known peers is not in this list when checkPeersWhoSentFloods(), that peer is dropped.
- Verify entire chain: When I receive all the blocks and make a blockchain, then I call validateBlockchain() method (in Blockchain class). This method call calculateHash() (in Block class) method on each Block to calculate the hash (with the hashlib code given by the Professor) in the list and compare the calculatedHash with the hash given in the Block. If calculatedHash of all blocks matches with the hash that is given in that block then this chain is considered valid. If this validation fails, then the entire chain is fetched again. 
- Choose longest chain (Ties break on which is the majority), or longest chain (ties break on majority): This is done in getStats() method. Here when the STATS_REPLY messages are received from all the peers, I find the maximum height. I also store the (height-hash pairs as keys) and (the list of peers who replied with that height-hash pair as keys) in statsReply dictionary. Then I count the number of peers in the dictionary for height-hash pairs where height is maximum height. Then out of all such height-hash pairs I choose the height-hash pair which had maximum peers, so this way the maximum height and most agreed hash gets chosen.
- Edge Case: Edge cases for joining: A new block was added while peer is doing Consensus: Here I store that Announce Block request and handle this request after finishing Consensus.
- Note: Consensus requests are ignored if already performing Consensus or when collecting FLOOD-REPLIES to update online peers list.
