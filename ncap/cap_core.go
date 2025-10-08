package ncap

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

// CapCore 抓包核心类
type CapCore struct{}

// NewCapCore 创建新的抓包核心
func NewCapCore() *CapCore {
	return &CapCore{}
}

// GetDevice 获取网卡设备
func (cc *CapCore) GetDevice(deviceName string) (*pcap.Handle, error) {
	// 查找所有网络设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("获取网卡列表失败: %v", err)
	}

	// 查找指定名称的设备
	for _, device := range devices {
		if device.Description == deviceName {
			// 打开设备
			handle, err := pcap.OpenLive(
				device.Name,
				1024*1024*10,
				true,
				pcap.BlockForever,
			)
			if err != nil {
				return nil, fmt.Errorf("无法打开网卡 %s: %v", device.Name, err)
			}
			return handle, nil
		}
	}

	return nil, fmt.Errorf("网卡设备不存在: %s", deviceName)
}

// Start 启动抓包
func (cc *CapCore) Start(deviceName string) error {
	device, err := cc.GetDevice(deviceName)
	if err != nil {
		return fmt.Errorf("获取网卡失败: %v", err)
	}
	capDevice := NewCapDevice(device, deviceName)
	return capDevice.Start()
}
