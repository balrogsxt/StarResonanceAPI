package ncap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/balrogsxt/StarResonanceAPI/global"
	"github.com/balrogsxt/StarResonanceAPI/pb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/klauspost/compress/zstd"
)

type CapDevice struct {
	deviceName    string
	device        *pcap.Handle
	currentServer string
	userUid       uint64 //当前玩家ID

	// TCP重组相关
	tcpMutex        sync.Mutex
	tcpDataBuffer   []byte
	tcpCacheTime    map[uint32]time.Time
	tcpCache        map[uint32][]byte // 修复：使用uint32避免类型转换溢出
	tcpStream       *bytes.Buffer
	tcpNextSeq      uint32 // 修复：使用uint32类型
	lastAnyPacketAt time.Time

	// 配置
	idleTimeout time.Duration
	gapTimeout  time.Duration

	// 服务器签名
	serverSignature      []byte
	loginReturnSignature []byte

	packetQueue *Queue[gopacket.Packet]
}

// NewCapDevice 创建新的抓包设备
func NewCapDevice(device *pcap.Handle, deviceName string) *CapDevice {
	return &CapDevice{
		deviceName:      deviceName,
		device:          device,
		tcpCache:        make(map[uint32][]byte), // 修复：使用uint32
		tcpCacheTime:    make(map[uint32]time.Time),
		tcpDataBuffer:   make([]byte, 0),
		tcpStream:       bytes.NewBuffer(nil),
		tcpNextSeq:      0, // 初始化为0而不是-1
		idleTimeout:     10 * time.Second,
		gapTimeout:      2 * time.Second,
		packetQueue:     NewQueue[gopacket.Packet](),
		serverSignature: []byte{0x00, 0x63, 0x33, 0x53, 0x42, 0x00},
		loginReturnSignature: []byte{
			0x00, 0x00, 0x00, 0x62,
			0x00, 0x03,
			0x00, 0x00, 0x00, 0x01,

			0x00, 0x11, 0x45, 0x14,

			0x00, 0x00, 0x00, 0x00,
			0x0a, 0x4e, 0x08, 0x01, 0x22, 0x24,
		},
	}
}

// Start 开始抓包
func (cd *CapDevice) Start() error {
	if cd.device == nil {
		return fmt.Errorf("网卡设备未设置")
	}

	// 设置过滤器
	err := cd.device.SetBPFFilter("ip and tcp")
	if err != nil {
		return fmt.Errorf("设置过滤器失败: %v", err)
	}

	log.Println("启动网络抓包: ", cd.deviceName)

	go func() {
		for {
			if packet, ok := cd.packetQueue.Dequeue(); ok {
				cd.handlePacket(packet)
			} else {
				time.Sleep(time.Millisecond * 50)
			}
		}
	}()

	// 开始捕获数据包
	packetSource := gopacket.NewPacketSource(cd.device, cd.device.LinkType())
	for packet := range packetSource.Packets() {
		if packet != nil {
			cd.packetQueue.Enqueue(packet)
		} else {
			log.Println("发现空的packet")
		}
	}
	log.Fatalf("数据包chan被关闭,中止运行")
	return nil
}

// handlePacket 处理单个数据包
func (cd *CapDevice) handlePacket(packet gopacket.Packet) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("handlePacket Panic:", err)
		}
	}()

	if packet == nil {
		log.Println("handlePacket 处理数据 == nil")
		return
	}
	if packet.NetworkLayer() == nil {
		log.Println("NetworkLayer == nil")
		return
	}
	if packet.Layers() == nil {
		log.Println("Layers == nil")
		return
	}
	// 提取TCP层

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}

	// 提取IP层
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return
	}

	// 获取TCP负载
	payload := tcp.Payload
	if len(payload) == 0 {
		return
	}

	// 构造服务器标识
	srcAddr := fmt.Sprintf("%s:%d", ip.SrcIP, tcp.SrcPort)
	revAddr := fmt.Sprintf("%s:%d", ip.DstIP, tcp.DstPort)
	srcServer := fmt.Sprintf("%s:%d -> %s:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
	revServer := fmt.Sprintf("%s:%d -> %s:%d", ip.DstIP, tcp.DstPort, ip.SrcIP, tcp.SrcPort)

	cd.tcpMutex.Lock()
	defer cd.tcpMutex.Unlock()
	now := time.Now()

	// 检查空闲超时
	if cd.currentServer != "" {
		if cd.currentServer == srcServer || cd.currentServer == revServer {
			cd.lastAnyPacketAt = now
		}
		//超时未识别到数据
		if cd.lastAnyPacketAt != (time.Time{}) && now.Sub(cd.lastAnyPacketAt) > cd.idleTimeout {
			cd.forceReconnect("idle timeout")
		}
	}
	// 服务器识别逻辑
	if cd.currentServer != srcServer && cd.currentServer != revServer {
		findGameServer := false
		//尝试通过小包识别服务器
		if len(payload) > 10 && payload[4] == 0 {
			data := payload[10:]
			if len(data) >= 4 { // 确保至少有4字节可读
				payloadMs := bytes.NewBuffer(data)
				for payloadMs.Len() >= 4 {
					var lenBuf [4]byte
					n, err := payloadMs.Read(lenBuf[:])
					if err != nil || n != 4 {
						break
					}

					msgLen := binary.BigEndian.Uint32(lenBuf[:])
					// 更严格的长度检查
					if msgLen < 4 || msgLen > uint32(payloadMs.Len()) || msgLen > 0x0FFFFFFF {
						break
					}

					// 确保有足够的数据可读
					if uint32(payloadMs.Len()) < msgLen-4 {
						break
					}

					tmp := make([]byte, msgLen-4)
					n, err = payloadMs.Read(tmp)
					if err != nil || uint32(n) != msgLen-4 {
						break
					}

					// 检查服务器签名 - 增强边界检查
					sigLen := len(cd.serverSignature)
					if len(tmp) < 5+sigLen {
						break
					}
					if !bytes.Equal(tmp[5:5+sigLen], cd.serverSignature) {
						break
					}
					if cd.currentServer != srcServer {
						cd.currentServer = srcServer
						cd.clearTcpCache()
						cd.tcpNextSeq = tcp.Seq + uint32(len(payload))
						global.ClearAllData()
						log.Println("识别游戏服务器: ", srcAddr)
						findGameServer = true
						break
					}
				}
			}
		}

		// 尝试通过登录返回包识别服务器
		if len(payload) == 0x62 {
			if bytes.Equal(payload[0:10], cd.loginReturnSignature[0:10]) &&
				bytes.Equal(payload[14:20], cd.loginReturnSignature[14:20]) {
				//设置新的游戏服务器标识
				cd.currentServer = srcServer
				cd.clearTcpCache()
				cd.tcpNextSeq = tcp.Seq + uint32(len(payload))
				global.ClearAllData()
				log.Println("识别游戏服务器: ", srcAddr)
				findGameServer = true
			}
		}
		if len(payload) >= 6 {
			if payload[4] == 0 && payload[5] == 5 {
				data := payload[10:]
				if len(data) >= 4 { // 确保至少有4字节可读
					reader := bytes.NewReader(data)
					for {
						lenBuf := make([]byte, 4)
						n, err := reader.Read(lenBuf)
						if err != nil || n != 4 {
							break
						}
						length := binary.BigEndian.Uint32(lenBuf)
						if length < 4 || length > 0x0FFFFFFF {
							break
						}
						remaining := reader.Len()
						if int(length-4) > remaining {
							break
						}
						data1 := make([]byte, length-4)
						n, err = reader.Read(data1)
						if err != nil || uint32(n) != length-4 {
							break
						}
						//检查签名
						signature := []byte{0x00, 0x06, 0x26, 0xad, 0x66, 0x00}
						sigLen := len(signature)
						if len(data1) < 5+sigLen {
							break
						}

						if !bytes.Equal(data1[5:5+sigLen], signature) {
							break
						}

						if cd.currentServer != revServer {
							global.ClearAllData()
							cd.currentServer = revServer
							cd.clearTcpCache()
							cd.tcpNextSeq = tcp.Ack
							log.Println("识别游戏服务器: ", revAddr)
							findGameServer = true
							break
						}
					}
				}
			}
		}
		if !findGameServer {
			//log.Println("不是游戏服务器: ", srcServer)
			return
		}
	}
	if len(cd.currentServer) == 0 {
		//log.Println("等待识别到游戏服务器")
		return
	}
	// TCP流重组
	cd.reassembleTcpStream(tcp, payload, now)
}

// reassembleTcpStream TCP流重组
func (cd *CapDevice) reassembleTcpStream(tcp *layers.TCP, payload []byte, now time.Time) {
	// 初始化序列号
	if cd.tcpNextSeq == 0 {
		if len(payload) > 4 && binary.BigEndian.Uint32(payload) < 0x0fffff {
			cd.tcpNextSeq = tcp.Seq
			log.Println("可以i确定学列号")
		} else {
			// 无法确定初始序列号，使用当前包的序列号
			cd.tcpNextSeq = tcp.Seq
			log.Println("无法缺点序列号")
		}
	}
	// 缓存TCP数据包
	seqKey := tcp.Seq
	cd.tcpCache[seqKey] = make([]byte, len(payload))
	copy(cd.tcpCache[seqKey], payload)
	cd.tcpCacheTime[seqKey] = now

	// 定期清理过期的缓存
	cd.cleanupOldCache(now)

	// 顺序拼接数据
	messageBuffer := bytes.NewBuffer(nil)
	currentSeq := cd.tcpNextSeq

	for {
		if data, exists := cd.tcpCache[currentSeq]; exists {
			messageBuffer.Write(data)
			delete(cd.tcpCache, currentSeq)
			delete(cd.tcpCacheTime, currentSeq)

			cd.tcpNextSeq = currentSeq + uint32(len(data))
			currentSeq = cd.tcpNextSeq
			cd.lastAnyPacketAt = now
		} else {
			break
		}
	}

	// 追加到TCP流
	if messageBuffer.Len() > 0 {
		cd.tcpStream.Write(messageBuffer.Bytes())
	}
	// 解析消息
	cd.parseMessages()
}

// parseMessages 解析消息
func (cd *CapDevice) parseMessages() {
	// 保存当前数据
	currentData := cd.tcpStream.Bytes()
	dataLen := len(currentData)
	offset := 0
	for offset < dataLen {
		// 检查是否有足够的字节读取长度
		if offset+4 > dataLen {
			break
		}

		// 读取包长度
		packetSize := binary.BigEndian.Uint32(currentData[offset : offset+4])
		if packetSize <= 4 || packetSize > 0x0FFFFF {
			break
		}

		// 检查是否有完整的包
		if offset+int(packetSize) > dataLen {
			break
		}

		// 提取完整包
		messagePacket := make([]byte, packetSize)
		copy(messagePacket, currentData[offset:offset+int(packetSize)])

		// 处理消息
		cd.handleProcess(messagePacket)

		// 移动偏移
		offset += int(packetSize)
	}

	// 更新流，只保留未处理的数据
	if offset > 0 {
		remaining := currentData[offset:]
		cd.tcpStream.Reset()
		cd.tcpStream.Write(remaining)
	}
}

// handleProcess 处理数据包
func (cd *CapDevice) handleProcess(packets []byte) {
	if len(packets) < 4 {
		return // 数据包太小
	}

	reader := NewByteReader(packets)
	for reader.Remaining() > 0 {
		// 读取包长度
		packetSize, ok := reader.TryPeekUInt32BE()
		if !ok {
			break
		}
		// 更严格的边界检查
		if packetSize < 6 || packetSize > uint32(reader.Remaining()) || packetSize > 0x0FFFFFFF {
			break
		}

		// 确保 packetSize 不会导致整数溢出
		if int(packetSize) < 0 || int(packetSize) > reader.Remaining() {
			break
		}

		// 读取完整包
		packetData, err := reader.ReadBytes(int(packetSize))
		if err != nil {
			break
		}

		// 验证包数据的完整性
		if len(packetData) < 6 {
			continue
		}

		packetReader := NewByteReader(packetData)
		sizeAgain, err := packetReader.ReadUInt32BE()
		if err != nil || sizeAgain != packetSize {
			continue
		}

		// 读取消息类型
		packetType, err := packetReader.ReadUInt16BE()
		if err != nil {
			continue
		}

		isZstdCompressed := (packetType & 0x8000) != 0
		msgTypeId := packetType & 0x7FFF

		// 分发到对应处理方法
		//log.Println(fmt.Sprintf("msgTypeId=%d", msgTypeId))
		cd.dispatchMessage(msgTypeId, packetReader, isZstdCompressed)
	}
}

// dispatchMessage 分发消息
func (cd *CapDevice) dispatchMessage(msgTypeId uint16, reader *ByteReader, isZstdCompressed bool) {
	switch msgTypeId {
	case 2: // NotifyMsg
		cd.processNotifyMsg(reader, isZstdCompressed)
	case 6: // FrameDown
		cd.processFrameDown(reader, isZstdCompressed)
	}
}

// processNotifyMsg 处理Notify消息
func (cd *CapDevice) processNotifyMsg(reader *ByteReader, isZstdCompressed bool) {
	serviceUuid, err := reader.ReadUInt64BE()
	if err != nil {
		return
	}

	_, err = reader.ReadUInt32BE()
	if err != nil {
		return
	}

	methodId, err := reader.ReadUInt32BE()
	if err != nil {
		return
	}
	if serviceUuid != 0x0000000063335342 {
		return
	}

	msgPayload := reader.ReadRemaining()
	if isZstdCompressed {
		msgPayload = cd.decompressZstdIfNeeded(msgPayload)
	}

	cd.processNotifyMethod(methodId, msgPayload)
}

// processFrameDown 处理FrameDown消息
func (cd *CapDevice) processFrameDown(reader *ByteReader, isZstdCompressed bool) {
	if _, err := reader.ReadUInt32BE(); err != nil {
		return
	}

	if reader.Remaining() == 0 {
		return
	}

	nestedPacket := reader.ReadRemaining()
	if isZstdCompressed {
		nestedPacket = cd.decompressZstdIfNeeded(nestedPacket)
	}

	cd.handleProcess(nestedPacket) // 递归解析内部消息
}

// processNotifyMethod 处理Notify方法
func (cd *CapDevice) processNotifyMethod(methodId uint32, payload []byte) {
	//log.Println(methodId)
	switch methodId {
	case 0x03: //场景切换
		cd.processSyncSceneData(payload)
	case 0x00000006: // 同步周边玩家实体
		cd.processSyncNearEntities(payload)
	case 0x00000015: // 同步自身完整容器数据
		cd.processSyncContainerData(payload)
	case 0x00000016: // 同步自身部分更新
	case 0x0000002E: // 同步自己受到的增量伤害
		cd.processSyncToMeDeltaInfo(payload)
	case 0x0000002D: // 同步周边增量伤害
		cd.processSyncNearDeltaInfo(payload)
	}
}

// decompressZstdIfNeeded ZSTD解压
func (cd *CapDevice) decompressZstdIfNeeded(buffer []byte) []byte {
	if len(buffer) < 4 {
		return buffer
	}

	decoder, err := zstd.NewReader(bytes.NewReader(buffer))
	if err != nil {
		return buffer
	}
	defer decoder.Close()

	result, err := io.ReadAll(decoder)
	if err != nil {
		return buffer
	}

	return result
}

// forceReconnect 强制重连
func (cd *CapDevice) forceReconnect(reason string) {
	log.Println("[PacketAnalyzer] Reconnect due to ", reason, time.Now().Format("15:04:05"))
	cd.resetCaptureState()
}
func (cd *CapDevice) forceResyncTo(seq uint32) {
	log.Println("[PacketAnalyzer] Resync to seq= ", seq)
	cd.tcpNextSeq = 0                     // 修复：重置为0
	cd.tcpCache = make(map[uint32][]byte) // 修复：使用uint32
	cd.tcpCacheTime = make(map[uint32]time.Time)
	cd.tcpStream.Reset()
}

// resetCaptureState 重置捕获状态
func (cd *CapDevice) resetCaptureState() {
	cd.currentServer = "" //清空当前服务器
	cd.clearTcpCache()
}

// clearTcpCache 清空TCP缓存
func (cd *CapDevice) clearTcpCache() {
	cd.tcpNextSeq = 0 // 修复：重置为0
	cd.tcpStream.Reset()

	cd.tcpCache = make(map[uint32][]byte) // 修复：使用uint32
	cd.tcpCacheTime = make(map[uint32]time.Time)
}

// cleanupOldCache 清理过期的TCP缓存，防止内存泄漏
func (cd *CapDevice) cleanupOldCache(now time.Time) {
	// 每100个包清理一次，避免频繁清理
	if len(cd.tcpCache) < 100 {
		return
	}

	// 清理超过gapTimeout的缓存
	for seq, timestamp := range cd.tcpCacheTime {
		if now.Sub(timestamp) > cd.gapTimeout {
			delete(cd.tcpCache, seq)
			delete(cd.tcpCacheTime, seq)
		}
	}

	// 如果缓存仍然过大，清理最旧的一半
	if len(cd.tcpCache) > 1000 {
		count := 0
		for seq := range cd.tcpCache {
			if count >= 500 {
				break
			}
			delete(cd.tcpCache, seq)
			delete(cd.tcpCacheTime, seq)
			count++
		}
		log.Printf("TCP缓存过大，已清理%d个过期条目", count)
	}
}

func (cd *CapDevice) processSyncSceneData(payload []byte) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("解析场景切换数据失败", err)
		}
	}()
	//未知的proto格式,暂时读取字节解析场景名称
	start := 43
	if start >= len(payload) {
		return
	}
	length := int(payload[42])
	if start+length > len(payload) {
		length = len(payload) - start
	}
	if start+length > len(payload) {
		return
	}
	text := string(payload[start : start+length])
	pattern := regexp.MustCompile("([\u4e00-\u9fa5]+)")
	name := pattern.FindString(text)
	if len(strings.Trim(name, " ")) > 0 {
		log.Println("场景切换: ", name)
		global.UpdateScene(func(info *global.SceneInfo) {
			if info != nil && info.Scene != nil {
				info.Scene.Name = name
			}
		})
	} else {
		log.Println("场景切换: 未知场景名称")
		global.UpdateScene(func(info *global.SceneInfo) {
			if info != nil && info.Scene != nil {
				info.Scene.Name = ""
			}
		})
	}
}

// processSyncNearEntities 处理同步周边实体
func (cd *CapDevice) processSyncNearEntities(payload []byte) {
	var msg pb.SyncNearEntities
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Println("解析proto失败", err.Error())
		return
	}
	//消失的怪物
	if msg.Disappear != nil && len(msg.Disappear) > 0 {
		for _, item := range msg.GetDisappear() {
			uuid := uint64(item.GetUuid())
			if uuid > 0 && isMonsterUUID(uuid) {
				entityId := uuid >> 16
				if item.GetDisappearType() == pb.EDisappearType_EDisappearDead {
					global.FindMonsterId(entityId, func(monster *global.Monster) {
						monster.Hp = 0
					})
				}
			}
		}
	}

	if msg.Appear == nil || len(msg.Appear) == 0 {
		return
	}
	//已存在怪物
	for _, item := range msg.GetAppear() {
		attrs := item.Attrs
		entityId := uint64(item.Uuid >> 16)
		switch item.EntityType {
		case pb.EEntityType_EntMonster:
			monsterAttr(entityId, attrs)
		}
	}
}
func monsterAttr(entityId uint64, attrs *pb.AttrCollection) {
	//怪物数据
	global.FindMonsterId(entityId, func(monster *global.Monster) {
		for _, attr := range attrs.GetAttrs() {
			if attr.Id == nil || attr.RawData == nil {
				continue
			}
			switch attr.GetId() {
			case 0x01: //名称
				value, n := protowire.ConsumeString(attr.RawData)
				if n > 0 && len(value) > 0 {
					log.Println(fmt.Sprintf("发现怪物: %s#%d", value, entityId))
					monster.Name = value
				}
			case 0x0A: //怪物模板ID
				value, n := protowire.ConsumeVarint(attr.RawData)
				if n > 0 {
					monster.TemplateId = value
					if name, has := global.MonsterNames[value]; has {
						log.Println(fmt.Sprintf("发现怪物: %s#%d", name, entityId))
						monster.Name = name
					}
				}
			case 0x2C2E: //当前血量
				value, n := protowire.ConsumeVarint(attr.RawData)
				if n == 0 || len(attr.RawData) == 0 {
					monster.Hp = 0
				} else {
					monster.Hp = value
				}
			case 0x2C38: //最大血量
				value, n := protowire.ConsumeVarint(attr.RawData)
				if n > 0 {
					monster.MaxHp = value
				}
			}
		}
	})
}

// processSyncContainerData 处理同步自身完整容器数据
func (cd *CapDevice) processSyncContainerData(payload []byte) {
	var msg pb.SyncContainerData
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Println(len(payload), "解析SyncContainerData失败", err.Error())
		return
	}
	if msg.VData == nil {
		return
	}
	vdata := msg.VData
	global.UpdateScene(func(info *global.SceneInfo) {
		if info == nil {
			return
		}

		// 更新玩家ID
		if vdata.CharId > 0 {
			if info.Player != nil {
				info.Player.Id = uint64(vdata.CharId)
			}
		}

		// 更新玩家战斗力
		if vdata.CharBase != nil {
			if point := vdata.CharBase.GetFightPoint(); point > 0 {
				if info.Player != nil {
					info.Player.FightPoint = point
				}
			}
			if v := vdata.CharBase.GetName(); len(v) > 0 {
				if info.Player != nil {
					info.Player.Name = v
				}
			}
			if v := vdata.GetRoleLevel(); v != nil {
				if v.Level > 0 && info.Player != nil {
					info.Player.Level = v.Level
				}
			}
		}

		// 更新玩家血量
		if vdata.Attr != nil {
			if info.Player != nil {
				info.Player.Hp = vdata.Attr.GetCurHp()
				if v := vdata.Attr.GetMaxHp(); v > 0 {
					info.Player.MaxHp = v
				}
			}
		}

		if vdata.SceneData != nil {
			//更新场景数据
			mapId := vdata.SceneData.GetMapId()   //场景地图ID
			lineId := vdata.SceneData.GetLineId() //场景线路ID
			// 更新场景信息
			if info.Scene != nil {
				//先收到线路数据,然后在收到坐标数据
				if info.Scene.MapId != mapId {
					//清空坐标
					if info.Player != nil {
						info.Player.Pos = nil
					}
				}
				info.Scene.MapId = mapId
				info.Scene.LineId = lineId
			}
		}
	})
}

// processSyncToMeDeltaInfo 处理同步自身增量伤害
func (cd *CapDevice) processSyncToMeDeltaInfo(payload []byte) {
	var msg pb.SyncToMeDeltaInfo
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Println("解析SyncToMeDeltaInfo失败", err.Error())
		return
	}
	info := msg.DeltaInfo
	if info.Uuid == nil {
		return
	}
	if info.BaseDelta == nil {
		return
	}
	baseDelta := info.GetBaseDelta()
	if info.Uuid != nil && cd.userUid != uint64(info.GetUuid()) {
		cd.userUid = uint64(info.GetUuid())
		log.Println(fmt.Sprintf("获取到当前玩家UUID: %d UID: %d", cd.userUid, cd.userUid>>16))
		global.UpdateScene(func(sceneInfo *global.SceneInfo) {
			if sceneInfo != nil && sceneInfo.Player != nil {
				sceneInfo.Player.Id = cd.userUid >> 16
			}
		})
	}
	//获取自身其他信息
	if baseDelta.Attrs != nil && baseDelta.Attrs.Attrs != nil && len(baseDelta.Attrs.Attrs) > 0 {
		for _, attr := range baseDelta.Attrs.GetAttrs() {
			switch attr.GetId() {
			case 53: //坐标数据解析
				var posMsg pb.Vector3
				if err := proto.Unmarshal(attr.GetRawData(), &posMsg); err != nil {
					log.Println("解析坐标数据失败: ", err.Error())
					continue
				}
				global.UpdateScene(func(sceneInfo *global.SceneInfo) {
					if sceneInfo != nil && sceneInfo.Player != nil {
						//log.Println("当前坐标:", posMsg.GetX(), posMsg.GetY(), posMsg.GetZ())
						sceneInfo.Player.Pos = &global.Position{
							X: posMsg.GetX(),
							Y: posMsg.GetY(),
							Z: posMsg.GetZ(),
						}
					}
				})
			}
		}
	}
	//其他数据同步
	ProcessAoiSyncDelta(baseDelta)
}

// processSyncNearDeltaInfo 处理同步周边增量伤害
func (cd *CapDevice) processSyncNearDeltaInfo(payload []byte) {
	var msg pb.SyncNearDeltaInfo
	if err := proto.Unmarshal(payload, &msg); err != nil {
		log.Println("解析SyncNearDeltaInfo失败", err.Error())
		return
	}
	if msg.DeltaInfos == nil || len(msg.DeltaInfos) == 0 {
		return
	}

	for _, item := range msg.DeltaInfos {
		ProcessAoiSyncDelta(item)
	}
}
func ProcessAoiSyncDelta(data *pb.AoiSyncDelta) {
	if data == nil {
		return
	}
	var targetUuidRaw = uint64(data.GetUuid())
	if targetUuidRaw == 0 {
		return
	}
	var isTargetPlayer = isPlayerUUID(targetUuidRaw)
	var targetUuid = targetUuidRaw >> 16
	if data.Attrs == nil {
		return
	}
	var attrCollection = data.Attrs
	if attrCollection.Attrs != nil {
		if !isTargetPlayer {
			monsterAttr(targetUuid, attrCollection)
		}
	}

	//技能伤害
	if data.SkillEffects == nil {
		return
	}
	var skillEffects = data.GetSkillEffects()
	if skillEffects.Damages == nil {
		return
	}
	for _, item := range skillEffects.Damages {
		if item.OwnerId == nil {
			continue
		}
		attackerUuid := uint64(item.GetTopSummonerId() | item.GetAttackerUuid())
		if attackerUuid == 0 {
			continue
		}
		isAttackerPlayer := isPlayerUUID(attackerUuid) //伤害来源是否是玩家
		attackerUuid = attackerUuid >> 16

		isDead := item.GetIsDead()                      //是否死亡
		isHeal := item.GetType() == pb.EDamageType_Heal //是否治疗

		if !isTargetPlayer { //非玩家目标
			if !isHeal {
				if isAttackerPlayer {
					global.FindMonsterId(targetUuid, func(monster *global.Monster) {
						if monster.AttackPlayers == nil {
							monster.AttackPlayers = make(map[uint64]*global.AttackPlayer)
						}
						player, has := monster.AttackPlayers[attackerUuid]
						if !has {
							player = &global.AttackPlayer{
								LastAttackTime: time.Now().Unix(),
							}
						} else {
							player.LastAttackTime = time.Now().Unix()
						}
						monster.AttackPlayers[attackerUuid] = player
					})
				}
			}
			//更新怪物坐标
			if item.DamagePos != nil {
				global.FindMonsterId(targetUuid, func(monster *global.Monster) {
					monster.Pos = &global.Position{
						X: item.DamagePos.GetX(),
						Y: item.DamagePos.GetY(),
						Z: item.DamagePos.GetZ(),
					}
				})
			}
			if isDead { //怪物死亡时移除血量
				global.FindMonsterId(targetUuid, func(monster *global.Monster) {
					monster.Hp = 0
				})
			}
		}

	}
}
func isPlayerUUID(uuid uint64) bool {
	return (uuid & 0xFFFF) == 640
}
func isMonsterUUID(uuid uint64) bool {
	return (uuid & 0xFFFF) == 64
}
