import random
import socket
import json
import sys
import threading
import uuid
import time
import hashlib

DIFFICULTY = 8

peersHosts = []
peersPorts = []
trustableHostsPortsPairs = []
floodMessagesIds = []       # List of IDs with which already received FLOOD messages

receivedFloodsFromPeers = []

hostPort = 8306
announceBlockHostPort = 8308
hostName = socket.gethostname()

currentMessages = ["Hello everyone!", hostName]
messagesBuffer = []

blockchain = None

blockAnnouncedWhileConsensus = False
announcedBlocksWhileConsensus = []

message = "Peer on " + hostName

# ========================================================================================================================================================================

class Block:
    def __init__(self, height, miner, nonce, messages, hash, timestamp):
        self.hash = hash
        self.height = height
        self.miner = miner
        self.nonce = nonce
        self.messages = messages
        self.timestamp = timestamp

    def getHeight(self):
        return self.height

    def getHash(self):
        return self.hash

    def getMessages(self):
        return self.messages

    def getMiner(self):
        return self.miner

    def getNonce(self):
        return self.nonce

    def getNonceLength(self):
        return len(str(self.nonce))

    def getTimestamp(self):
        return self.timestamp

    def setHash(self, newHash):
        self.hash = newHash

    def calculateHash(self, lastBlockHash, difficulty):
        hashBase = hashlib.sha256()
        # get the most recent hash
        # lastHash = lastBlockHash

        # add it to this hash
        hashBase.update(lastBlockHash.encode())

        # add the miner
        hashBase.update(self.miner.encode())

        # add the messages in order
        for m in self.messages:
            hashBase.update(m.encode())

        # The timestamp, make it into a 64 bit byte string
        hashBase.update(self.timestamp.to_bytes(8, 'big'))

        # add the nonce
        hashBase.update(self.nonce.encode())

        # get the pretty hexadecimal
        hash = hashBase.hexdigest()

        # is it difficult enough? Do I have enough zeros?
        if hash[-1 * difficulty:] != '0' * difficulty:
            return None

        return hash

    def blocksEqual(self, otherBlock):
        if (self.hash == otherBlock.getHash()) and (self.height == otherBlock.getHeight()) and (self.miner == otherBlock.getMiner()) and (self.nonce == otherBlock.getNonce()) and (self.messages == otherBlock.getMessages()) and (self.timestamp == otherBlock.getTimestamp()):
            return True
        else:
            return False
# ========================================================================================================================================================================

class Blockchain:
    def __init__(self, height):
        self.height = height
        self.blocksList = [None] * self.height

    def getHeight(self):
        return self.height

    def getBlockslist(self):
        return self.blocksList

    def getMaximumBlockHash(self):
        if self.height >= 1:
            return self.blocksList[self.height - 1].getHash()
        else:
            return ''

    def getBlock(self, index):
        if index is not None and isinstance(index, int) and 0 <= index < self.height:
            return self.blocksList[index]

    def addBlock(self, newBlock):
        if newBlock.getHeight() is not None and isinstance(newBlock.getHeight(), int) and 0 <= newBlock.getHeight() < self.height:
            self.blocksList[newBlock.getHeight()] = newBlock

    def addNewBlockInBlockchain(self, newBlock):
        self.blocksList.append(newBlock)
        self.height = len(self.blocksList)
        print("Added the new announced block to the blockchain")

    def addNewAnnouncedBlock(self, newBlock):
        if newBlock.getHeight() is not None and isinstance(newBlock.getHeight(), int) and newBlock.getHeight() == self.height:
            self.addNewBlockInBlockchain(newBlock)
        else:
            print("Cannot add the block because of inappropriate height")

    def allBlocksPresent(self):
        allPresent = True

        for i in range(self.height):
            if self.blocksList[i] is None:
                allPresent = False

        return allPresent

    def findMissingBlocks(self):
        missingBlocksIndices = []

        for i in range(self.height):
            if self.blocksList[i] is None:
                missingBlocksIndices.append(i)

        return missingBlocksIndices

    def validateBlockchain(self):
        valid = True
        lastHash = ''

        for i in range(self.height):
            if self.blocksList[i].getNonceLength() > 40:
                print("Nonce of the block is more than 40 characters")
                return False

            calculatedHash = self.blocksList[i].calculateHash(lastHash, DIFFICULTY)

            if calculatedHash == None:
                return False

            if calculatedHash != self.blocksList[i].getHash():
                valid = False

            lastHash = self.blocksList[i].getHash()

        return valid

    def blockchainsEqual(self, otherBlockchain):
        if self.height != otherBlockchain.getHeight():
            return False
        else:
            for i in range(self.height):
                if not self.blocksList[i].blocksEqual(otherBlockchain.getBlock(i)):
                    return False

        return True

    def updateBlockchain(self, newBlockchain):
        self.height = newBlockchain.getHeight()
        self.blocksList = newBlockchain.getBlockslist()
# ========================================================================================================================================================================

def getBlocksRequest(clientSocket, hostPortPair, blockHeight):
    getBlocks = {
        "type": "GET_BLOCK",
        "height": blockHeight
    }
    getBlocksRequest = json.dumps(getBlocks)
    clientSocket.sendto(getBlocksRequest.encode("utf-8"), hostPortPair)
# ========================================================================================================================================================================

def getBlocksRepy(blockchain, reply):
    if ('height' in reply.keys() and reply['height'] is not None and isinstance(reply['height'], int)) and ('minedBy' in reply.keys()) and ('nonce' in reply.keys()) and ('messages' in reply.keys()) and ('hash' in reply.keys() and reply['hash'] is not None) and ('timestamp' in reply.keys()):
        newBlock = Block(reply['height'], reply['minedBy'], reply['nonce'], reply['messages'], reply['hash'], reply['timestamp'])
        blockchain.addBlock(newBlock)
# ========================================================================================================================================================================

def getAllBlocks(blockchain, clientSocket, trustableHostsPortsPairs):
    foundAllBlocks = False
    tries = 0

    while foundAllBlocks is False and tries < 10:
        missingBlocksIndices = blockchain.findMissingBlocks()

        for i in range(len(missingBlocksIndices)):
            getBlocksRequest(clientSocket, random.choice(trustableHostsPortsPairs), missingBlocksIndices[i])

        timeout = time.time() + 2

        while time.time() < timeout:
            response, addr = clientSocket.recvfrom(4096)
            responseStr = response.decode('utf-8')
            reply = json.loads(responseStr)

            if 'type' in reply.keys() and reply['type'] == "GET_BLOCK_REPLY":
                getBlocksRepy(blockchain, reply)
            elif 'type' in reply.keys() and reply['type'] == "FLOOD":
                handleFloodRequest(reply, clientSocket, hostName, hostPort, peersHosts, peersPorts)
            elif 'type' in reply.keys() and reply['type'] == "STATS":
                sendBusyStatsReply(addr, clientSocket)
            elif 'type' in reply.keys() and reply['type'] == "GET_BLOCK":
                sendBusyGetBlockReply(clientSocket, addr)
            elif 'type' in reply.keys() and reply['type'] == "NEW_WORD":
                handleAddNewWord(reply)
            elif 'type' in reply.keys() and reply['type'] == "ANNOUNCE":    # if a new block is announced while we are fetching blocks for consensus, then we will handle this announcement request after finishing this consensus
                global blockAnnouncedWhileConsensus
                blockAnnouncedWhileConsensus = True
                announcedBlocksWhileConsensus.append(reply)

        if blockchain.allBlocksPresent() is True:
            foundAllBlocks = True
# ========================================================================================================================================================================

def getEntireBlockchain(clientSocket, trustableHostsPortsPairs, height):
    blockchain = Blockchain(height)

    # Sending "GET-BLOCK" messages
    for i in range(height):
        getBlocksRequest(clientSocket, random.choice(trustableHostsPortsPairs), i)

    timeout = time.time() + 2

    while time.time() < timeout:
        response, addr = clientSocket.recvfrom(4096)
        responseStr = response.decode('utf-8')
        reply = json.loads(responseStr)

        if 'type' in reply.keys() and reply['type'] == "GET_BLOCK_REPLY":
            getBlocksRepy(blockchain, reply)
        elif 'type' in reply.keys() and reply['type'] == "FLOOD":
            handleFloodRequest(reply, clientSocket, hostName, hostPort, peersHosts, peersPorts)
        elif 'type' in reply.keys() and reply['type'] == "STATS":
            sendBusyStatsReply(addr, clientSocket)
        elif 'type' in reply.keys() and reply['type'] == "GET_BLOCK":
            sendBusyGetBlockReply(clientSocket, addr)
        elif 'type' in reply.keys() and reply['type'] == "NEW_WORD":
            handleAddNewWord(reply)
        elif 'type' in reply.keys() and reply['type'] == "ANNOUNCE":  # if a new block is announced while we are fetching blocks for consensus, then we will handle this announcement request after finishing this consensus (fetching blockchain from peers)
            global blockAnnouncedWhileConsensus
            blockAnnouncedWhileConsensus = True
            announcedBlocksWhileConsensus.append(reply)

    if blockchain.allBlocksPresent() is False:
        getAllBlocks(blockchain, clientSocket, trustableHostsPortsPairs)

    return blockchain
# ========================================================================================================================================================================

def fetchNewBlockchain(clientSocket, trustableHostsPortsPairs, height):
    foundValidBlockchain = False
    blockchain = None

    while foundValidBlockchain is False:
        blockchain = getEntireBlockchain(clientSocket, trustableHostsPortsPairs, height)

        if blockchain.allBlocksPresent() is True:
            validate = blockchain.validateBlockchain()

            if validate is True:
                foundValidBlockchain = True
                print("Got the valid Blockchain")

    return blockchain
# ========================================================================================================================================================================

def handleFloodRequest(request, clientSocket, hostName, hostPort, peersHosts, peersPorts):
    if 'host' in request.keys() and 'id' in request.keys():
        clientHost = request['host']

        if 'port' in request.keys():
            clientPort = request['port']

            receivedFloodsFromPeers.append((clientHost, clientPort))

            message = "Peer on " + hostName

            floodReply = {
                "type": "FLOOD_REPLY",
                "host": hostName,
                "port": hostPort,
                "name": message
            }

            floodReplyStr = json.dumps(floodReply)

            clientSocket.sendto(floodReplyStr.encode("utf-8"), (clientHost, clientPort))

            # Forwarding the FLOOD messages to all the known peers for the first time received FLOOD message from this client
            if request['id'] not in floodMessagesIds:
                floodMessagesIds.append(request['id'])

                requestAsStr = json.dumps(request)

                for i in range(len(peersHosts)):
                    clientSocket.sendto(requestAsStr.encode("utf-8"), (peersHosts[i], peersPorts[i]))
                    print("Forwarding FLOOD message to ", (peersHosts[i], peersPorts[i]), ": ", requestAsStr)
# ========================================================================================================================================================================

def handleStatsRequest(blockchain, addr, clientSocket):
    statsReply = {
        "type": "STATS_REPLY",
        "height": blockchain.getHeight(),
        "hash": blockchain.getMaximumBlockHash()
    }

    statsReplyAsStr = json.dumps(statsReply)

    clientSocket.sendto(statsReplyAsStr.encode("utf-8"), addr)
    print("Sending STATS-REPLY to ", addr, ": ", statsReplyAsStr)
# ========================================================================================================================================================================

def sendBusyStatsReply(addr, clientSocket):
    busyStatsReply = {
        "type": "STATS_REPLY",
        "height": None,
        "hash": "Busy doing some other operation right now."
    }

    busyStatsReplyAsStr = json.dumps(busyStatsReply)

    clientSocket.sendto(busyStatsReplyAsStr.encode("utf-8"), addr)
    print("Sending busy STATS-REPLY to ", addr, ": ", busyStatsReplyAsStr)
# ========================================================================================================================================================================

def handleGetBlockRequest(request, blockchain, addr, clientSocket):
    height = None
    if 'height' in request.keys():
        height = request['height']

    getBlockReply = {
        "type": "GET_BLOCK_REPLY",
        "hash": None,
        "height": None,
        "messages": None,
        "minedBy": None,
        "nonce": None,
        "timestamp": None
    }

    if height is not None and isinstance(height, int) and 0 <= height < blockchain.getHeight():
        block = blockchain.getBlock(height)

        getBlockReply = {
            "type": "GET_BLOCK_REPLY",
            "hash": block.getHash(),
            "height": block.getHeight(),
            "messages": block.getMessages(),
            "minedBy": block.getMiner(),
            "nonce": block.getNonce(),
            "timestamp": block.getTimestamp()
        }

    getBlockReplyStr = json.dumps(getBlockReply)

    clientSocket.sendto(getBlockReplyStr.encode("utf-8"), addr)
    print("Sending GET_BLOCK_REPLY to ", addr, ": ", getBlockReplyStr)
# ========================================================================================================================================================================

def sendBusyGetBlockReply(clientSocket, addr):
    busyGetBlockReply = {
        "type": "GET_BLOCK_REPLY",
        "hash": "Busy doing some other operation right now",
        "height": None,
        "messages": None,
        "minedBy": None,
        "nonce": None,
        "timestamp": None
    }

    busyGetBlockReplyStr = json.dumps(busyGetBlockReply)

    clientSocket.sendto(busyGetBlockReplyStr.encode("utf-8"), addr)
    print("Sending busy GET_BLOCK_REPLY to ", addr, ": ", busyGetBlockReplyStr)
# ========================================================================================================================================================================

def handleAnnounceRequest(request, blockchain):
    if ('height' in request.keys() and request['height'] is not None and isinstance(request['height'], int)) and ('minedBy' in request.keys()) and ('nonce' in request.keys()) and ('messages' in request.keys()) and ("hash" in request.keys() and request['hash'] is not None) and ('timestamp' in request.keys()):
        newBlock = Block(request['height'], request['minedBy'], request['nonce'], request['messages'], request['hash'], request['timestamp'])

        lastBlockHash = blockchain.getMaximumBlockHash()
        calculatedHash = newBlock.calculateHash(lastBlockHash, DIFFICULTY)

        if calculatedHash is not None:
            blockchain.addNewAnnouncedBlock(newBlock)
# ========================================================================================================================================================================

def handleConsensusRequest(currentBlockchain, clientSocket, trustableHostsPortsPairs):
    print("Performing Consensus")
    height = getStats(clientSocket)
    latestBlockchain = fetchNewBlockchain(clientSocket, trustableHostsPortsPairs, height)

    # Handling any announce requests that came in while doing consensus
    if blockAnnouncedWhileConsensus:
        for announcement in announcedBlocksWhileConsensus:
            handleAnnounceRequest(announcement, clientSocket)

    if currentBlockchain.blockchainsEqual(latestBlockchain):
        print("Our blockchain is the same as the latest blockchain")
    else:
        print("Rebuilding blockchain")
        currentBlockchain.updateBlockchain(latestBlockchain)
# ========================================================================================================================================================================

def updateMessages(newMessage):
    if len(currentMessages) < 10:
        currentMessages.append(newMessage)
    else:
        messagesBuffer.append(newMessage)
# ========================================================================================================================================================================

def handleAddNewWord(request):
    if "word" in request.keys() and request["word"] is not None and isinstance(request["word"], str) and len(request["word"]) <= 20:
        newWord = request["word"]
        updateMessages(newWord)
    else:
        print("Inappropriate word in NEW_WORD request")
# ========================================================================================================================================================================

def checkBuffer():
    if len(messagesBuffer) != 0:
        currentMessages.clear()

    for i in range(len(currentMessages), 10):
        if len(messagesBuffer) != 0:
            currentMessages.append(messagesBuffer.pop(0))
# ========================================================================================================================================================================

def announceNewBlock(newBlock, blockchain):
    announce = {
        "type": "ANNOUNCE",
        "height": newBlock.getHeight(),
        "minedBy": newBlock.getMiner(),
        "nonce": newBlock.getNonce(),
        "messages": newBlock.getMessages(),
        "timestamp": newBlock.getTimestamp(),
        "hash": newBlock.getHash()
    }

    consensus = {
        "type": "CONSENSUS"
    }

    announceAsStr = json.dumps(announce)
    consensusAsStr = json.dumps(consensus)

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.bind((hostName, announceBlockHostPort))

    for i in range(len(peersHosts)):
        clientSocket.sendto(announceAsStr.encode("utf-8"), (peersHosts[i], peersPorts[i]))

    for i in range(len(peersHosts)):
        clientSocket.sendto(consensusAsStr.encode("utf-8"), (peersHosts[i], peersPorts[i]))

    # Announce this block to this server as well to update the blockchain
    handleAnnounceRequest(announce, blockchain)
# ========================================================================================================================================================================

def createRandomBlock(currentBlockchain, nonceValue):
    height = currentBlockchain.getHeight()
    minedBy = "Rishavjot Singh"
    messages = currentMessages
    timestamp = int(time.time())
    nonce = str(nonceValue)
    hash = ''
    return Block(height, minedBy, nonce, messages, hash, timestamp)
# ========================================================================================================================================================================

def mineBlocks():
    count = 0
    nonceValue = 0
    while True:
        nonceValue = (nonceValue + 1) % sys.maxsize
        lastBlockHash = blockchain.getMaximumBlockHash()
        newBlock = createRandomBlock(blockchain, nonceValue)
        hash = newBlock.calculateHash(lastBlockHash, DIFFICULTY)

        if hash is not None:
            print("Mined new block", count)
            count += 1
            newBlock.setHash(hash)
            announceNewBlock(newBlock, blockchain)
            checkBuffer()       # To update the messages
# ========================================================================================================================================================================

def getStats(clientSocket):
    statsReplies = {}
    trustableHostsPortsPairs.clear()    # Clearing the previous list to recollect the new trustable peers which have the
    heightsList = []

    # Now we need to send STATS message to everyone
    stats = {
        "type": "STATS"
    }

    statsAsStr = json.dumps(stats)

    # Sending STATS request to known peers
    for i in range(len(peersHosts)):
        clientSocket.sendto(statsAsStr.encode("utf-8"), (peersHosts[i], peersPorts[i]))

    timeout = time.time() + 2

    while time.time() < timeout:
        response, addr = clientSocket.recvfrom(4096)
        responseStr = response.decode('utf-8')
        reply = json.loads(responseStr)

        print(addr, reply)

        if 'type' in reply.keys() and reply['type'] == "STATS_REPLY" and 'height' in reply.keys() and reply['height'] is not None and isinstance(reply['height'], int) and 'hash' in reply.keys():
            heightHash = (reply['height'], reply['hash'])
            heightsList.append(reply['height'])

            if heightHash in statsReplies.keys():
                statsReplies[heightHash].append(addr)
            else:
                statsReplies[heightHash] = []
                statsReplies[heightHash].append(addr)
        elif 'type' in reply.keys() and reply['type'] == "FLOOD":
            handleFloodRequest(reply, clientSocket, hostName, hostPort, peersHosts, peersPorts)
        elif 'type' in reply.keys() and reply['type'] == "STATS":
            sendBusyStatsReply(addr, clientSocket)
        elif 'type' in reply.keys() and reply['type'] == "GET_BLOCK":
            sendBusyGetBlockReply(clientSocket, addr)
        elif 'type' in reply.keys() and reply['type'] == "NEW_WORD":
            handleAddNewWord(reply)

    maxHeight = 0

    if len(heightsList) > 0:
        maxHeight = max(heightsList)

    heightHashPairs = list(statsReplies)
    heightHashPairsCount = []

    for i in range(len(statsReplies)):
        heightHashPairsCount.append(0)

    for i in range(len(statsReplies)):
        heightHashPair = heightHashPairs[i]

        # Counting the height-hash pairs with the longest length
        if heightHashPair[0] is not None and isinstance(heightHashPair[0], int) and heightHashPair[0] == maxHeight:
            heightHashPairsCount[i] += 1

    maxCount = 0

    # Finding the maximum count of peers who agree on same hash with the longest length
    for i in range(len(heightHashPairsCount)):
        if heightHashPairsCount[i] > maxCount:
            maxCount = heightHashPairsCount[i]

    height = maxHeight

    # Collecting the trustable peers who have the most agreed hash with the longest chain
    for i in range(len(statsReplies)):
        if heightHashPairsCount[i] == maxCount:
            for j in range(len(statsReplies[heightHashPairs[i]])):
                trustableHostsPortsPairs.append(statsReplies[heightHashPairs[i]][j])

    print("The height of the blockchain is ", height)

    return height
# ========================================================================================================================================================================

def sendFloodMessages(clientSocket, blockchain):
    id = str(uuid.uuid4())

    floodRequest = {
        "type": "FLOOD",
        "host": hostName,
        "port": hostPort,
        "id": id,
        "name": message
    }

    msg = json.dumps(floodRequest)

    for i in range(len(peersHosts)):
        clientSocket.sendto(msg.encode("utf-8"), (peersHosts[i], peersPorts[i]))
        print("Sending FLOOD message to ", (peersHosts[i], peersPorts[i]), ": ", msg)

    timeout = time.time() + 2

    while time.time() < timeout:
        response, addr = clientSocket.recvfrom(4096)

        responseStr = response.decode('utf-8')
        reply = json.loads(responseStr)

        print(addr, reply)

        if 'type' in reply.keys() and reply['type'] == "FLOOD_REPLY" and 'host' in reply.keys() and 'port' in reply.keys():
            if reply['host'] not in peersHosts:
                peersHosts.append(reply['host'])
                peersPorts.append(reply['port'])
            else:
                foundSamePort = False

                for i in range(len(peersHosts)):
                    if peersHosts[i] == reply['host'] and peersPorts[i] == reply['port']:
                        foundSamePort = True

                if not foundSamePort:                   # if we didn't know about this peer then add then collect this peer's details
                    peersHosts.append(reply['host'])
                    peersPorts.append(reply['port'])
        elif 'type' in reply.keys() and reply['type'] == "FLOOD":
            handleFloodRequest(reply, clientSocket, hostName, hostPort, peersHosts, peersPorts)
        elif 'type' in reply.keys() and reply['type'] == "STATS":
            sendBusyStatsReply(addr, clientSocket)
        elif 'type' in reply.keys() and reply['type'] == "GET_BLOCK":
            sendBusyGetBlockReply(clientSocket, addr)
        elif 'type' in reply.keys() and reply['type'] == "NEW_WORD":
            handleAddNewWord(reply)
        elif 'type' in reply.keys() and reply['type'] == "ANNOUNCE":
            handleAnnounceRequest(reply, blockchain)
# ========================================================================================================================================================================

def checkPeersWhoSentFloods():
    print("Dropping peers that didn't send FLOOD messages")

    for i in range(len(peersHosts)):
        peer = (peersHosts[i], peersPorts[i])
        if i < len(peersHosts) and (len(peersHosts) == len(peersPorts)) and (peer not in receivedFloodsFromPeers):  # then drop that peer
            peersHosts.pop(i)
            peersPorts.pop(i)

    receivedFloodsFromPeers.clear()
# ========================================================================================================================================================================

def main():
    serverHost = 'silicon.cs.umanitoba.ca'
    serverPort = 8999

    serverHost2 = 'eagle.cs.umanitoba.ca'
    serverPort2 = 8999

    peersHosts.append(serverHost)
    peersPorts.append(serverPort)

    peersHosts.append(serverHost2)
    peersPorts.append(serverPort2)

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.bind((hostName, hostPort))

    id = str(uuid.uuid4())

    floodRequest = {
        "type": "FLOOD",
        "host": hostName,
        "port": hostPort,
        "id": id,
        "name": message
    }

    msg = json.dumps(floodRequest)

    with clientSocket:
        # Sending FLOOD message to well-known host
        print("Sending FLOOD message to well-known host")
        clientSocket.sendto(msg.encode("utf-8"), (serverHost, serverPort))
        timeout = time.time() + 2

        while time.time() < timeout:
            response, addr = clientSocket.recvfrom(4096)
            responseStr = response.decode('utf-8')
            reply = json.loads(responseStr)

            print(addr, reply)

            if 'type' in reply.keys() and reply['type'] == "FLOOD_REPLY" and 'host' in reply.keys() and 'port' in reply.keys():
                peersHosts.append(reply['host'])
                peersPorts.append(reply['port'])
            elif 'type' in reply.keys() and reply['type'] == "FLOOD":
                handleFloodRequest(reply, clientSocket, hostName, hostPort, peersHosts, peersPorts)
            elif 'type' in reply.keys() and reply['type'] == "STATS":
                sendBusyStatsReply(addr, clientSocket)
            elif 'type' in reply.keys() and reply['type'] == "GET_BLOCK":
                sendBusyGetBlockReply(clientSocket, addr)
            elif 'type' in reply.keys() and reply['type'] == "NEW_WORD":
                handleAddNewWord(reply)

        height = getStats(clientSocket)

        global blockchain
        if len(trustableHostsPortsPairs) == 0 or height is 0:
            blockchain = Blockchain(0)
        else:
            blockchain = fetchNewBlockchain(clientSocket, trustableHostsPortsPairs, height)

            # Handling any announce requests that came in while doing consensus (fetching blockchain from peers)
            if blockAnnouncedWhileConsensus:
                for announcement in announcedBlocksWhileConsensus:
                    handleAnnounceRequest(announcement, clientSocket)

        print("Trying to mine")
        newThread = threading.Thread(target=mineBlocks, args=())
        newThread.start()

        # Respond to messages
        while True:
            requestMessage, addr = clientSocket.recvfrom(4096)
            requestStr = requestMessage.decode('utf-8')
            request = json.loads(requestStr)

            print(addr, request)

            if 'type' in request.keys() and request['type'] == "FLOOD":
                handleFloodRequest(request, clientSocket, hostName, hostPort, peersHosts, peersPorts)
            elif 'type' in request.keys() and request['type'] == "STATS":
                handleStatsRequest(blockchain, addr, clientSocket)
            elif 'type' in request.keys() and request['type'] == "GET_BLOCK":
                handleGetBlockRequest(request, blockchain, addr, clientSocket)
            elif 'type' in request.keys() and request['type'] == "ANNOUNCE":
                handleAnnounceRequest(request, blockchain)
            elif 'type' in request.keys() and request['type'] == "CONSENSUS":
                handleConsensusRequest(blockchain, clientSocket, trustableHostsPortsPairs)
            elif 'type' in request.keys() and request['type'] == "NEW_WORD":
                handleAddNewWord(request)

            # Send FLOOD messages every 30 seconds
            if int(time.time()) % 30 == 0:
                print("Sending FLOOD messages")
                sendFloodMessages(clientSocket, blockchain)

            # Check from which peers we have received FLOOD messages in a minute (60 seconds)
            if int(time.time()) % 60 == 0:
                checkPeersWhoSentFloods()

            # Perform Consensus every 300 seconds (5 minutes)
            if int(time.time()) % 300 == 0:
                print("Need to perform Consensus")
                handleConsensusRequest(blockchain, clientSocket, trustableHostsPortsPairs)

# ========================================================================================================================================================================

main()