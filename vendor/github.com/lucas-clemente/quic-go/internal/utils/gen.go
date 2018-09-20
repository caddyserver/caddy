package utils

//go:generate genny -pkg utils -in linkedlist/linkedlist.go -out byteinterval_linkedlist.go gen Item=ByteInterval
//go:generate genny -pkg utils -in linkedlist/linkedlist.go -out packetinterval_linkedlist.go gen Item=PacketInterval
