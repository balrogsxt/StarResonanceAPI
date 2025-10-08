package global

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"log"
)

//go:embed monster_names.json
var MonsterNamesJson string

var MonsterNames map[uint64]string

func InitMonsterNames() {
	if err := json.Unmarshal(bytes.NewBufferString(MonsterNamesJson).Bytes(), &MonsterNames); err != nil {
		log.Fatalln("加载怪物映射表解析错误: ", err.Error())
	}
	log.Println("怪物映射表加载完成,加载数量: ", len(MonsterNames))
}
