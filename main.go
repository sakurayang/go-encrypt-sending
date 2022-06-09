package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"go-crypto-sending/src/sending/client"
	"go-crypto-sending/src/sending/server"
	"net"
	"os"
)

type connectionCallbackFunction func(net.Conn)

func StartServer(listenAddress string, connectionCallbackFunction connectionCallbackFunction) {
	listen, err := net.Listen("tcp", listenAddress)
	if err != nil {
		fmt.Println("错误: ", err.Error())
		return
	}

	fmt.Println("等待客户端连接至", listenAddress)

	for {
		connection, err := listen.Accept()
		if err != nil {
			fmt.Println("无法与客户端建立连接:", err.Error())
		}
		fmt.Println("客户端 " + connection.RemoteAddr().String() + " 已连接.")
		connectionCallbackFunction(connection)
	}

}

func ConnectToServer(serverAddress string, connectionCallbackFunction connectionCallbackFunction) {
	connection, err := net.Dial("tcp", serverAddress)
	if err != nil {
		fmt.Println("无法连接至服务器:", err.Error())
	}
	connectionCallbackFunction(connection)
}

func main() {
	parser := argparse.NewParser("d", "d")
	mode := parser.String("m", "mode", &argparse.Options{Required: true, Help: "运行模式： server - 服务器模式，client - 客户端模式"})
	address := parser.String("a", "address", &argparse.Options{Required: true, Help: "服务端 (监听) 地址，例：localhost:8000"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Println("选项错误: ", err.Error())
		return
	}
	if *mode != "server" && *mode != "client" {
		fmt.Println("运行模式仅能选择 server 或 client")
		return
	}
	if *mode == "server" {
		StartServer(*address, server.Handle)
	} else {
		ConnectToServer(*address, client.Handle)
	}
}
