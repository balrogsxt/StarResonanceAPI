package global

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// 场景怪物数据
var SceneMonsterList = make(map[uint64]*Monster)
var SceneMonsterListLock = sync.RWMutex{}

var CurrentScene *SceneInfo = nil
var CurrentSceneLock = sync.RWMutex{}

type SceneInfo struct {
	Scene  *SceneData   `json:"scene"`  //当前场景信息
	Player *ScenePlayer `json:"player"` //当前场景自己的信息
}
type SceneData struct {
	MapId  uint32 `json:"map_id"`  //场景ID
	Name   string `json:"name"`    //场景名称
	LineId uint32 `json:"line_id"` //场景线路ID
}
type ScenePlayer struct {
	Id         uint64    `json:"id"`            //自己ID
	FightPoint int32     `json:"fight_point"`   //评分
	Name       string    `json:"name"`          //自己昵称
	Level      int32     `json:"level"`         //玩家等级
	Hp         int64     `json:"hp"`            //当前血量
	MaxHp      int64     `json:"max_hp"`        //最大血量
	Pos        *Position `json:"pos,omitempty"` //自己坐标
}

type Position struct {
	X float32 `json:"x"`
	Y float32 `json:"y"`
	Z float32 `json:"z"`
}
type AttackPlayer struct {
	Name           string `json:"name,omitempty"` //玩家昵称
	LastAttackTime int64  `json:"-"`              //最后攻击时间
}
type Monster struct {
	Name          string                   `json:"name,omitempty"`           //怪物名称
	Hp            uint64                   `json:"hp"`                       //当前血量
	MaxHp         uint64                   `json:"max_hp,omitempty"`         //最大血量
	Pos           *Position                `json:"pos,omitempty"`            //怪物坐标
	TemplateId    uint64                   `json:"template_id,omitempty"`    //模板ID
	EntityId      uint64                   `json:"entity_id,omitempty"`      //当前敌人ID
	AttackPlayers map[uint64]*AttackPlayer `json:"attack_players,omitempty"` //正在攻击的玩家列表
	UpdateTime    int64                    `json:"-"`                        //数据最后更新时间
}

func ClearAllData() {
	clearMonsterList()
}
func clearMonsterList() {
	SceneMonsterListLock.Lock()
	defer SceneMonsterListLock.Unlock()
	SceneMonsterList = make(map[uint64]*Monster)
}

//func clearScene() {
//	CurrentSceneLock.Lock()
//	defer CurrentSceneLock.Unlock()
//	//玩家坐标去掉,场景切换其他信息不会变动,但是如果是网络中断导致的重新识别服务器会导致当前场景数据被清空
//	if CurrentScene != nil && CurrentScene.Player != nil{
//		CurrentScene.Player.Pos = nil
//	}
//}

func FindMonsterId(uuid uint64, callback func(*Monster)) {
	var monster *Monster
	var isNew bool

	// 加锁获取或创建monster对象
	SceneMonsterListLock.Lock()
	if existing, has := SceneMonsterList[uuid]; has {
		monster = existing
		isNew = false
	} else {
		monster = &Monster{
			UpdateTime: time.Now().Unix(),
		}
		SceneMonsterList[uuid] = monster
		isNew = true
	}
	SceneMonsterListLock.Unlock()

	// 在锁外调用callback，避免死锁和长时间持锁
	startTime := time.Now()
	callback(monster)

	// 记录性能指标
	duration := time.Since(startTime).Milliseconds()
	if duration >= 100 {
		log.Println(fmt.Sprintf("%d 异常更新耗时: %d ms", uuid, duration))
	}

	// 如果不是新创建的对象，需要更新时间戳
	if !isNew {
		SceneMonsterListLock.Lock()
		if currentMonster, exists := SceneMonsterList[uuid]; exists {
			currentMonster.UpdateTime = time.Now().Unix()
		}
		SceneMonsterListLock.Unlock()
	}
}

func UpdateScene(callback func(*SceneInfo)) {
	CurrentSceneLock.Lock()
	defer CurrentSceneLock.Unlock()
	if CurrentScene == nil {
		CurrentScene = &SceneInfo{
			Player: &ScenePlayer{},
			Scene:  &SceneData{},
		}
	}
	callback(CurrentScene)

}
