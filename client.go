package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"

	//"math/rand", not "crypto/rand"
	"net"
	"os"
	"sync"
	"time"
)

type Client struct {
	nodeID        int
	url           string
	keypair       Keypair
	knownNodes    []*KnownNode
	request       *RequestMsg
	replyLog      map[int]*ReplyMsg
	mutex         sync.Mutex
	replyGovCount int
	replyNorCount int
}

func NewClient(clientID int) *Client {
	client := &Client{
		ClientNode.nodeID,
		ClientNode.url,
		KeypairMap[ClientNode.nodeID],
		KnownAllNodes,
		nil,
		make(map[int]*ReplyMsg),
		sync.Mutex{},
		0,
		0,
	}
	return client
}

func (c *Client) Start() {
	c.sendRequest()

	ln, err := net.Listen("tcp", c.url)
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go c.handleConnection(conn)
	}
}

func (c *Client) handleConnection(conn net.Conn) {
	req, err := ioutil.ReadAll(conn)
	header, payload, _ := SplitMsg(req)
	if err != nil {
		panic(err)
	}
	switch header {
	case hGovReply, hNorReply:
		c.handleReply(payload)
	}
}

func (c *Client) sendRequest() {
	msg := fmt.Sprintf("%d work to do!", rand.Int())
	// msg := ReadFileString()
	req := Request{
		msg,
		hex.EncodeToString(generateDigest(msg)),
	}
	reqmsg := &RequestMsg{
		"solve",
		int(time.Now().Unix()),
		c.nodeID,
		req,
	}
	sig, err := c.signMessage(reqmsg)
	if err != nil {
		fmt.Printf("%v\n", err)
	}
	logBroadcastMsg(hRequest, reqmsg)
	send(ComposeMsg(hRequest, reqmsg, sig), c.findPrimaryNode().url)
	c.request = reqmsg
}

func (c *Client) handleReply(payload []byte) {
	var replyMsg ReplyMsg
	err := json.Unmarshal(payload, &replyMsg)
	if err != nil {
		fmt.Printf("error happened:%v", err)
		return
	}
	if replyMsg.Header == "hGovReply" && c.replyGovCount == 0 {
		c.replyGovCount += 1
		logHandleMsg(c.nodeID, hGovReply, replyMsg, replyMsg.NodeID)
	}
	if replyMsg.Header == "hNorReply" && c.replyNorCount == 0 {
		c.replyNorCount += 1
		logHandleMsg(c.nodeID, hNorReply, replyMsg, replyMsg.NodeID)
	}
	if (c.replyGovCount + c.replyNorCount) == 2 {
		fmt.Println("request success end")
		PrintMemUsage()
		fmt.Println("end nano time:", time.Now().UnixNano())
		os.Exit(1)
	}
}

func (c *Client) signMessage(msg interface{}) ([]byte, error) {
	sig, err := signMessage(msg, c.keypair.privkey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (c *Client) findPrimaryNode() *KnownNode {
	nodeId := ViewID%len(c.knownNodes) + 4
	for _, knownNode := range c.knownNodes {
		if knownNode.nodeID == nodeId {
			return knownNode
		}
	}
	return nil
}

func (c *Client) countGovNeedReceiveMsgAmount() int {
	f := (len(KnownGovNodes) - 1) / 3
	return f + 1
}

func (c *Client) countNorNeedReceiveMsgAmount() int {
	f := (len(KnownNorNodes) - 1) / 3
	return f + 1
}
