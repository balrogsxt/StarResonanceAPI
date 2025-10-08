# StarResonanceApi
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-brightgreen.svg)](https://www.gnu.org/licenses/agpl-3.0.txt)

项目基于[StarResonanceDamageCounter](https://github.com/dmlgzs/StarResonanceDamageCounter)实现的方案开放更多的一些详细数据API

### 前置要求

- npcap


## 启动方式

请在命令行下启动exe文件即可,自定义参数请按照下方参考

## 启动参数

| 参数              | 类型     | 默认值  | 说明                                  |
|-----------------|--------|------|-------------------------------------|
| --network       | string | auto | 网卡描述,auto为自动选择网卡                    |
| --expire        | int    | 10   | 怪物数据包超时时间(秒),一定时间后未收到怪物数据包,则认为消失或死亡 |
| --port          | int    | 8989 | API开放端口                             |
| --autoCheckTime | int    | 3    | 自动探测活动网卡等待时间(秒)                        |


## 开放API
> GET /api/enemies

获取敌方数据
```json
{
    "code": 0,
    "msg": "OK",
    "enemy": {
        //怪物实体ID
        "15247": {
            "name": "山贼斧手", //怪物名称
            "hp": 9728, //当前血量
            "max_hp": 10992, //最大血量
            "pos": { //实时移动坐标
                "x": 191.65988,
                "y": 185.6441,
                "z": 433.85992
            },
            "template_id": 10027, //怪物模板ID
            "entity_id": 15247, //怪物实体ID
            "attack_players": { //当前攻击的玩家
                "35321": {
                    "name": "" //玩家昵称(暂无)
                }
            }
        }
    }
}
```

> GET /api/clear

清空所有统计数据

```json
{
  "code": 0,
  "msg": "OK"
}
```

> GET /api/scene

当前玩家的一些场景数据

```json
{
    "code": 0,
    "data": { //首次启动这里是null,需要切换一次地图
        "scene": {
            "map_id": 8, //地图ID
            "name": "阿斯特里斯", //场景名称
            "line_id": 1 //线路ID
        },
        "player": {
            "id": 1000, //玩家UID
            "fight_point": 25000, //能力评分
            "name": "玩家名称",
            "level": 60,
            "hp": 500, //当前血量(血量暂时不是实时的)
            "max_hp": 176429, //最大血量(血量暂时不是实时的)
            "pos": {//实时坐标数据
                "x": 106.075485,
                "y": 103.98257,
                "z": 54.675217
            }
        }
    },
    "msg": "OK"
}
```

## 致谢
- [StarResonanceDamageCounter](https://github.com/dmlgzs/StarResonanceDamageCounter)
- [StarResonanceData](https://github.com/PotRooms/StarResonanceData)

## 许可证
[![AGPLv3](https://www.gnu.org/graphics/agplv3-with-text-162x68.png)](LICENSE)

使用本项目即表示您同意遵守该许可证的条款。

本项目采用 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证
