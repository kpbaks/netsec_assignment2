# RFC 1071 - Computing the Internet Checksum
def ip_checksum(data: bytes) -> int:
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            checksum += (data[i] << 8) + data[i + 1]
        else:
            checksum += data[i] << 8
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = ~checksum & 0xffff
    return checksum
