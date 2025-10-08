package main

import (
	"StarResonanceAPI/global"
	"StarResonanceAPI/ncap"
	_ "embed"
	"flag"
	"fmt"
	"github.com/AlecAivazis/survey/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

var (
	networkCard   = flag.String("network", "auto", "请输入网卡描述完整名称,默认auto为自动选择")
	port          = flag.Int("port", 8989, "默认API端口")
	expireTime    = flag.Int64("expire", 10, "数据过期时间(秒),默认10s")
	autoCheckTime = flag.Int("autoCheckTime", 3, "自动检查活动网卡时间(秒)")
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Fatalf("程序崩溃: %v\n堆栈信息:\n%s", r, debug.Stack())
		}
	}()
	flag.Parse()
	var deviceName = *networkCard
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("获取网卡失败: ", err.Error())
	}
	if deviceName == "auto" {
		log.Println("正在自动查找活动网卡,请稍等...")
		active := ncap.GetActiveNetworkCards(devices, *autoCheckTime)
		if active != nil {
			log.Println("已自动找到合适的网卡: ", active.Desc)
			log.Println("监听数据包数量: ", active.PacketCount)
			log.Println("监听数据包流量: ", fmt.Sprintf("%d 字节 (%.2f KB)", active.ByteCount, float64(active.ByteCount)/1024))
			deviceName = active.Desc
		} else {
			var option string
			options := make([]string, 0)
			for _, device := range devices {
				options = append(options, device.Description)
			}
			prompt := &survey.Select{
				Message: "无法自动找到活动网卡,请手动选择活动网卡(可以在自己的网络设置中找到网卡查看描述):",
				Options: options,
			}
			err := survey.AskOne(prompt, &option)
			if err != nil {
				log.Fatalf("选择操作错误: %s", err.Error())
			}
			if len(option) == 0 {
				log.Fatalf("选择网卡为空")
			}
			deviceName = option
		}
	}

	// 加载怪物JSON列表
	global.InitMonsterNames()

	// 启动服务
	go Openapi()
	go OpenCap(deviceName)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	log.Println("程序已启动，按 Ctrl+C 退出")
	<-sigChan
	log.Println("正在关闭程序...")
}

func OpenCap(deviceName string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("抓包服务崩溃: %v\n堆栈信息:\n%s", r, debug.Stack())
		}
	}()

	// 创建抓包核心
	capCore := ncap.NewCapCore()
	if err := capCore.Start(deviceName); err != nil {
		log.Fatalf("启动抓包失败: %v", err)
	}
}
func Openapi() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("API服务崩溃: %v\n堆栈信息:\n%s", r, debug.Stack())
		}
	}()

	gin.SetMode(gin.ReleaseMode)
	s := gin.New()

	// 添加全局panic恢复中间件
	s.Use(gin.Recovery())

	s.GET("/api/enemies", func(ctx *gin.Context) {
		global.SceneMonsterListLock.RLock()
		defer global.SceneMonsterListLock.RUnlock()
		et := *expireTime
		if 0 >= et {
			et = 10
		}
		list := make(map[uint64]*global.Monster)
		for id, item := range global.SceneMonsterList {
			if time.Now().Unix()-item.UpdateTime > et {
				continue //忽略10秒没更新的数据
			}
			attackPlayers := make(map[uint64]*global.AttackPlayer)
			if item.AttackPlayers != nil {
				for uid, player := range item.AttackPlayers {
					if time.Now().Unix()-player.LastAttackTime > et { //忽略10秒没参与战斗的玩家
						continue
					}
					attackPlayers[uid] = player
				}
			}
			if len(item.Name) > 0 || (item.Hp >= 0 && item.MaxHp > 0) {
				monsterCopy := *item
				monsterCopy.AttackPlayers = attackPlayers
				list[id] = &monsterCopy
			}
		}
		ctx.JSON(200, gin.H{
			"code":  0,
			"msg":   "OK",
			"enemy": list,
		})
	})
	s.GET("/api/clear", func(ctx *gin.Context) {
		global.ClearAllData()
		ctx.JSON(200, gin.H{
			"code": 0,
			"msg":  "OK",
		})
	})
	s.GET("/api/scene", func(ctx *gin.Context) {
		global.CurrentSceneLock.RLock()
		defer global.CurrentSceneLock.RUnlock()
		ctx.JSON(200, gin.H{
			"code": 0,
			"msg":  "OK",
			"data": global.CurrentScene,
		})
	})
	log.Println(fmt.Sprintf("服务启动在: http://127.0.0.1:%d", *port))
	if err := s.Run(fmt.Sprintf(":%d", *port)); err != nil {
		log.Fatalf(err.Error())
	}
}
