package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/bn256"
)

const ViewID = 0

type Node struct {
	NodeID      int
	knownNodes  []*KnownNode
	clientNode  *KnownNode
	sequenceID  int
	View        int
	msgQueue    chan []byte
	keypair     Keypair
	msgLog      *MsgLog
	requestPool map[string]*RequestMsg
	mutex       sync.Mutex
	nodeSK      *big.Int
	nodePK      *bn256.G2
	blslog      *BlsLog
}

type Keypair struct {
	privkey *rsa.PrivateKey
	pubkey  *rsa.PublicKey
}
type MsgLog struct {
	preprepareLog map[string]map[int]bool
	prepareLog    map[string]map[int]bool
	commitLog     map[string]map[int]bool
	replyLog      map[string]bool
}
type BlsLog struct {
	sigs []*bn256.G1
	pks  []*bn256.G2
	msgs []string
}

func NewNode(nodeID int) *Node {
	nodeSK, nodePK, _, _ := KeyGenerate()
	if nodeID <= 3 {
		return &Node{
			nodeID,
			KnownGovNodes,
			ClientNode,
			0,
			ViewID,
			make(chan []byte),
			KeypairMap[nodeID],
			&MsgLog{
				make(map[string]map[int]bool),
				make(map[string]map[int]bool),
				make(map[string]map[int]bool),
				make(map[string]bool),
			},
			make(map[string]*RequestMsg),
			sync.Mutex{},
			nodeSK,
			nodePK,
			&BlsLog{
				make([]*bn256.G1, 0),
				make([]*bn256.G2, 0),
				make([]string, 0),
			},
		}
	}
	if nodeID > 3 && nodeID <= 7 {
		return &Node{
			nodeID,
			KnownNorNodes,
			ClientNode,
			0,
			ViewID,
			make(chan []byte),
			KeypairMap[nodeID],
			&MsgLog{
				make(map[string]map[int]bool),
				make(map[string]map[int]bool),
				make(map[string]map[int]bool),
				make(map[string]bool),
			},
			make(map[string]*RequestMsg),
			sync.Mutex{},
			nodeSK,
			nodePK,
			&BlsLog{
				make([]*bn256.G1, 0, 0),
				make([]*bn256.G2, 0, 0),
				make([]string, 0, 0),
			},
		}
	}
	return nil
}

func (node *Node) getSequenceID() int {
	seq := node.sequenceID
	node.sequenceID++
	return seq
}

func (node *Node) Start() {
	go node.handleMsg()
}

func (node *Node) handleMsg() {
	for {
		msg := <-node.msgQueue
		header, payload, sign := SplitMsg(msg)
		switch header {
		case hRequest:
			node.handleRequest(payload, sign)
		case hPrePrepare:
			node.handlePrePrepare(payload, sign)
		case hPrepare:
			node.handlePrepare(payload, sign)
		}
	}
}

func (node *Node) handleRequest(payload []byte, sig []byte) {
	var request RequestMsg
	var prePrepareMsg PrePrepareMsg
	var blssig *bn256.G1
	err := json.Unmarshal(payload, &request)
	if err != nil {
		fmt.Printf("error happened:%v", err)
		return
	}
	logHandleMsg(node.NodeID, hRequest, request, request.ClientID)
	// verify request's digest
	vdig := verifyDigest(request.CliRequest.Message, request.CliRequest.Digest)
	if vdig == false {
		fmt.Printf("verifyDigest failed\n")
		return
	}
	//verigy request's signature
	_, err = verifySignatrue(request, sig, node.clientNode.pubkey)
	if err != nil {
		fmt.Printf("verify signature failed:%v\n", err)
		return
	}
	node.mutex.Lock()
	node.requestPool[request.CliRequest.Digest] = &request
	seqID := node.getSequenceID()
	node.mutex.Unlock()
	blssig = Sign(node.nodeSK, request.String())
	prePrepareMsg = PrePrepareMsg{
		request,
		request.CliRequest.Digest,
		ViewID,
		seqID,
		blssig.Marshal(),
		node.nodePK.Marshal(),
	}
	//sign prePrepareMsg
	msgSig, err := node.signMessage(prePrepareMsg)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	msg := ComposeMsg(hPrePrepare, prePrepareMsg, msgSig)
	node.mutex.Lock()

	// put preprepare msg into log
	if node.msgLog.preprepareLog[prePrepareMsg.Digest] == nil {
		node.msgLog.preprepareLog[prePrepareMsg.Digest] = make(map[int]bool)
	}
	node.msgLog.preprepareLog[prePrepareMsg.Digest][node.NodeID] = true
	node.mutex.Unlock()
	node.knownNodes = KnownAllNodes
	logBroadcastMsg(hPrePrepare, prePrepareMsg)
	node.broadcast(msg)
}

func (node *Node) handlePrePrepare(payload []byte, sig []byte) {
	var prePrepareMsg PrePrepareMsg
	err := json.Unmarshal(payload, &prePrepareMsg)
	if err != nil {
		fmt.Printf("error happened:%v", err)
		return
	}
	pnodeId := node.findPrimaryNode()
	logHandleMsg(node.NodeID, hPrePrepare, prePrepareMsg, pnodeId)
	var msgPubkey *rsa.PublicKey
	if node.NodeID <= 3 {
		msgPubkey = node.findGovNodePubkey(pnodeId)
	} else {
		msgPubkey = node.findNodePubkey(pnodeId)
	}
	if msgPubkey == nil {
		fmt.Println("can't find primary node's public key")
		return
	}
	// verify msg's signature
	_, err = verifySignatrue(prePrepareMsg, sig, msgPubkey)
	if err != nil {
		fmt.Printf("verify signature failed:%v\n", err)
		return
	}
	// verify prePrepare's digest is equal to request's digest
	if prePrepareMsg.Digest != prePrepareMsg.Request.CliRequest.Digest {
		fmt.Printf("verify digest failed\n")
		return
	}
	node.mutex.Lock()
	node.requestPool[prePrepareMsg.Request.CliRequest.Digest] = &prePrepareMsg.Request
	node.mutex.Unlock()
	err = node.verifyRequestDigest(prePrepareMsg.Digest)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	// put preprepare's msg into log
	node.mutex.Lock()
	if node.msgLog.preprepareLog[prePrepareMsg.Digest] == nil {
		node.msgLog.preprepareLog[prePrepareMsg.Digest] = make(map[int]bool)
	}
	node.msgLog.preprepareLog[prePrepareMsg.Digest][pnodeId] = true
	node.mutex.Unlock()
	var sendMsg []byte
	node.blslog.msgs = append(node.blslog.msgs, prePrepareMsg.Request.String())
	blssig, _ := new(bn256.G1).Unmarshal(prePrepareMsg.BlsSig)
	node.blslog.sigs = append(node.blslog.sigs, blssig)
	nodepk, _ := new(bn256.G2).Unmarshal(prePrepareMsg.BlsPK)
	node.blslog.pks = append(node.blslog.pks, nodepk)

	blssig = Sign(node.nodeSK, prePrepareMsg.Digest)

	prepareMsg := PrepareMsg{
		prePrepareMsg.Digest,
		ViewID,
		prePrepareMsg.SequenceID,
		node.NodeID,
		blssig.Marshal(),
		node.nodePK.Marshal(),
	}

	// sign prepare msg
	msgSig, err := signMessage(prepareMsg, node.keypair.privkey)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	sendMsg = ComposeMsg(hPrepare, prepareMsg, msgSig)

	node.mutex.Lock()
	// put prepare msg into log
	if node.msgLog.prepareLog[prepareMsg.Digest] == nil {
		node.msgLog.prepareLog[prepareMsg.Digest] = make(map[int]bool)
	}
	node.msgLog.prepareLog[prepareMsg.Digest][node.NodeID] = true
	node.mutex.Unlock()

	logBroadcastMsg(hPrepare, prepareMsg)
	node.broadcast(sendMsg)
}

func (node *Node) handlePrepare(payload []byte, sig []byte) {
	if node.NodeID > 3 {
		node.knownNodes = KnownNorNodes
	}
	var prepareMsg PrepareMsg
	err := json.Unmarshal(payload, &prepareMsg)
	if err != nil {
		fmt.Printf("error happened:%v", err)
		return
	}
	logHandleMsg(node.NodeID, hPrepare, prepareMsg, prepareMsg.NodeID)
	// verify prepareMsg
	pubkey := node.findNodePubkey(prepareMsg.NodeID)
	_, err = verifySignatrue(prepareMsg, sig, pubkey)
	if err != nil {
		fmt.Printf("verify signature failed:%v\n", err)
		return
	}
	// verify request's digest
	err = node.verifyRequestDigest(prepareMsg.Digest)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	// verify prepareMsg's digest is equal to preprepareMsg's digest
	pnodeId := node.findPrimaryNode()
	exist := node.msgLog.preprepareLog[prepareMsg.Digest][pnodeId]
	if !exist {
		fmt.Printf("this digest's preprepare msg by %d not existed\n", pnodeId)
		return
	}
	// put prepareMsg into log
	node.mutex.Lock()
	if node.msgLog.prepareLog[prepareMsg.Digest] == nil {
		node.msgLog.prepareLog[prepareMsg.Digest] = make(map[int]bool)
	}
	node.msgLog.prepareLog[prepareMsg.Digest][prepareMsg.NodeID] = true
	node.mutex.Unlock()

	blssig, _ := new(bn256.G1).Unmarshal(prepareMsg.BlsSig)
	nodepk, _ := new(bn256.G2).Unmarshal(prepareMsg.BlsPK)

	node.blslog.msgs = append(node.blslog.msgs, prepareMsg.Digest)
	node.blslog.sigs = append(node.blslog.sigs, blssig)
	node.blslog.pks = append(node.blslog.pks, nodepk)

	sum := len(node.blslog.msgs)
	if sum >= 3 {
		N := sum
		pks := make([]*bn256.G2, N, N)
		msgs := make([]string, N, N)
		sigs := make([]*bn256.G1, N, N)

		for i := 0; i < N; i++ {
			pks[i] = node.blslog.pks[i]
			msgs[i] = node.blslog.msgs[i]
			sigs[i] = node.blslog.sigs[i]
		}

		asig := Aggregate(sigs)
		ok := AVerify(asig, msgs, pks)

		if !ok {
			fmt.Println("aggregate signature failed")
		} else {
			fmt.Println("aggregate success")
			node.mutex.Lock()
			requestMsg := node.requestPool[prepareMsg.Digest]
			node.mutex.Unlock()
			done := "operation:" + requestMsg.Operation + ",message:" + requestMsg.CliRequest.Message
			//TODO:Add operations of destination clients
			var result string
			if node.NodeID <= 3 {
				result = "hGovReply"
				replyMsg := ReplyMsg{
					result,
					node.View,
					int(time.Now().Unix()),
					requestMsg.ClientID,
					node.NodeID,
					done,
				}
				logBroadcastMsg(hGovReply, replyMsg)
				send(ComposeMsg(hGovReply, replyMsg, []byte{}), node.clientNode.url)
			} else {
				result = "hNorReply"
				replyMsg := ReplyMsg{
					result,
					node.View,
					int(time.Now().Unix()),
					requestMsg.ClientID,
					node.NodeID,
					done,
				}
				logBroadcastMsg(hNorReply, replyMsg)
				send(ComposeMsg(hNorReply, replyMsg, []byte{}), node.clientNode.url)
				send(ComposeMsg(hNorReply, replyMsg, []byte{}), requestMsg.CliRequest.DestURL)
			}

		}
	}
}

//record the digest of each request
func (node *Node) verifyRequestDigest(digest string) error {
	node.mutex.Lock()
	_, ok := node.requestPool[digest]
	if !ok {
		node.mutex.Unlock()
		return fmt.Errorf("verify request digest failed\n")

	}
	node.mutex.Unlock()
	return nil
}

func (node *Node) findVerifiedPrepareMsgCount(digest string) (int, error) {
	sum := 0
	node.mutex.Lock()
	for _, exist := range node.msgLog.prepareLog[digest] {
		if exist == true {
			sum++
		}
	}
	node.mutex.Unlock()
	return sum, nil
}

func (node *Node) findVerifiedCommitMsgCount(digest string) (int, error) {
	sum := 0
	node.mutex.Lock()
	for _, exist := range node.msgLog.commitLog[digest] {

		if exist == true {
			sum++
		}
	}
	node.mutex.Unlock()
	return sum, nil
}

func (node *Node) broadcast(data []byte) {
	for _, knownNode := range node.knownNodes {
		if knownNode.nodeID != node.NodeID {
			err := send(data, knownNode.url)
			if err != nil {
				fmt.Printf("%v", err)
			}
		}
	}

}

func (node *Node) findGovNodePubkey(nodeId int) *rsa.PublicKey {
	for _, knownNode := range KnownAllNodes {
		if knownNode.nodeID == nodeId {
			return knownNode.pubkey
		}
	}
	return nil
}

func (node *Node) findNodePubkey(nodeId int) *rsa.PublicKey {
	for _, knownNode := range node.knownNodes {
		if knownNode.nodeID == nodeId {
			return knownNode.pubkey
		}
	}
	return nil
}

func (node *Node) signMessage(msg interface{}) ([]byte, error) {
	sig, err := signMessage(msg, node.keypair.privkey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func send(data []byte, url string) error {
	conn, err := net.Dial("tcp", url)
	if err != nil {
		return fmt.Errorf("%s is not online \n", url)
	}
	defer conn.Close()
	_, err = io.Copy(conn, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%v\n", err)
	}
	return nil
}

func (node *Node) findPrimaryNode() int {
	return ViewID%len(node.knownNodes) + 4
}

func (node *Node) countTolerateFaultNode() int {
	return (len(node.knownNodes) - 1) / 3
}

func (node *Node) countNeedReceiveMsgAmount() int {
	f := node.countTolerateFaultNode()
	return 2*f + 1
}
