package ncap

import (
	"encoding/binary"
	"io"
)

// ByteReader 字节读取器，用于处理大端序数据
type ByteReader struct {
	buffer []byte
	offset int
}

// NewByteReader 创建新的字节读取器
func NewByteReader(buffer []byte, offset ...int) *ByteReader {
	off := 0
	if len(offset) > 0 {
		off = offset[0]
	}
	return &ByteReader{
		buffer: buffer,
		offset: off,
	}
}

// Remaining 剩余可读字节数
func (br *ByteReader) Remaining() int {
	return len(br.buffer) - br.offset
}

// TryPeekUInt32BE 尝试读取大端序32位无符号整数（不移动偏移）
func (br *ByteReader) TryPeekUInt32BE() (uint32, bool) {
	if br.Remaining() < 4 {
		return 0, false
	}

	value := binary.BigEndian.Uint32(br.buffer[br.offset:])
	return value, true
}

// ReadUInt64BE 读取大端序64位无符号整数
func (br *ByteReader) ReadUInt64BE() (uint64, error) {
	if br.Remaining() < 8 {
		return 0, io.EOF
	}

	value := binary.BigEndian.Uint64(br.buffer[br.offset:])
	br.offset += 8
	return value, nil
}

// PeekUInt64BE 查看大端序64位无符号整数（不移动偏移）
func (br *ByteReader) PeekUInt64BE() (uint64, error) {
	if br.Remaining() < 8 {
		return 0, io.EOF
	}

	return binary.BigEndian.Uint64(br.buffer[br.offset:]), nil
}

// ReadUInt32BE 读取大端序32位无符号整数
func (br *ByteReader) ReadUInt32BE() (uint32, error) {
	if br.Remaining() < 4 {
		return 0, io.EOF
	}

	value := binary.BigEndian.Uint32(br.buffer[br.offset:])
	br.offset += 4
	return value, nil
}

// PeekUInt32BE 查看大端序32位无符号整数（不移动偏移）
func (br *ByteReader) PeekUInt32BE() (uint32, error) {
	if br.Remaining() < 4 {
		return 0, io.EOF
	}

	return binary.BigEndian.Uint32(br.buffer[br.offset:]), nil
}

// ReadUInt16BE 读取大端序16位无符号整数
func (br *ByteReader) ReadUInt16BE() (uint16, error) {
	if br.Remaining() < 2 {
		return 0, io.EOF
	}

	value := binary.BigEndian.Uint16(br.buffer[br.offset:])
	br.offset += 2
	return value, nil
}

// PeekUInt16BE 查看大端序16位无符号整数（不移动偏移）
func (br *ByteReader) PeekUInt16BE() (uint16, error) {
	if br.Remaining() < 2 {
		return 0, io.EOF
	}

	return binary.BigEndian.Uint16(br.buffer[br.offset:]), nil
}

// ReadBytes 读取指定长度的字节
func (br *ByteReader) ReadBytes(length int) ([]byte, error) {
	if length < 0 || br.Remaining() < length {
		return nil, io.EOF
	}

	result := make([]byte, length)
	copy(result, br.buffer[br.offset:br.offset+length])
	br.offset += length
	return result, nil
}

// PeekBytes 查看指定长度的字节（不移动偏移）
func (br *ByteReader) PeekBytes(length int) ([]byte, error) {
	if length < 0 || br.Remaining() < length {
		return nil, io.EOF
	}

	result := make([]byte, length)
	copy(result, br.buffer[br.offset:br.offset+length])
	return result, nil
}

// ReadRemaining 读取所有剩余字节
func (br *ByteReader) ReadRemaining() []byte {
	remaining := br.Remaining()
	if remaining == 0 {
		return []byte{}
	}

	result := make([]byte, remaining)
	copy(result, br.buffer[br.offset:])
	br.offset = len(br.buffer)
	return result
}
