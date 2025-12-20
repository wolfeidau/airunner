package util

import "google.golang.org/protobuf/proto"

func AsInt32(i int) int32 {
	if i > 2147483647 {
		return 2147483647
	}
	if i < -2147483648 {
		return -2147483648
	}
	// #nosec G115 - bounded by explicit check
	return int32(i)
}

// MarshalProto marshals a protobuf message to binary format
func MarshalProto(msg proto.Message) ([]byte, error) {
	return proto.Marshal(msg)
}

// UnmarshalProto unmarshals a protobuf message from binary format
func UnmarshalProto(data []byte, msg proto.Message) error {
	return proto.Unmarshal(data, msg)
}
