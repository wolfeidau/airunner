package util

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
