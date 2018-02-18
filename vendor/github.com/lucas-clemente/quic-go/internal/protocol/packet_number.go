package protocol

// InferPacketNumber calculates the packet number based on the received packet number, its length and the last seen packet number
func InferPacketNumber(packetNumberLength PacketNumberLen, lastPacketNumber PacketNumber, wirePacketNumber PacketNumber) PacketNumber {
	epochDelta := PacketNumber(1) << (uint8(packetNumberLength) * 8)
	epoch := lastPacketNumber & ^(epochDelta - 1)
	prevEpochBegin := epoch - epochDelta
	nextEpochBegin := epoch + epochDelta
	return closestTo(
		lastPacketNumber+1,
		epoch+wirePacketNumber,
		closestTo(lastPacketNumber+1, prevEpochBegin+wirePacketNumber, nextEpochBegin+wirePacketNumber),
	)
}

func closestTo(target, a, b PacketNumber) PacketNumber {
	if delta(target, a) < delta(target, b) {
		return a
	}
	return b
}

func delta(a, b PacketNumber) PacketNumber {
	if a < b {
		return b - a
	}
	return a - b
}

// GetPacketNumberLengthForHeader gets the length of the packet number for the public header
// it never chooses a PacketNumberLen of 1 byte, since this is too short under certain circumstances
func GetPacketNumberLengthForHeader(packetNumber PacketNumber, leastUnacked PacketNumber) PacketNumberLen {
	diff := uint64(packetNumber - leastUnacked)
	if diff < (1 << (uint8(PacketNumberLen2)*8 - 1)) {
		return PacketNumberLen2
	}
	return PacketNumberLen4
}

// GetPacketNumberLength gets the minimum length needed to fully represent the packet number
func GetPacketNumberLength(packetNumber PacketNumber) PacketNumberLen {
	if packetNumber < (1 << (uint8(PacketNumberLen1) * 8)) {
		return PacketNumberLen1
	}
	if packetNumber < (1 << (uint8(PacketNumberLen2) * 8)) {
		return PacketNumberLen2
	}
	if packetNumber < (1 << (uint8(PacketNumberLen4) * 8)) {
		return PacketNumberLen4
	}
	return PacketNumberLen6
}
