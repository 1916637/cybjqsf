"""私服 /agent 长连接。

客户端 connect() 成功后用 sendAsync 发 game_login，并等待服务端回带 resp 的帧。
doReceive 里只有 ~~n.resp > 0 才会 resolve _asyncList，缺 resp -> 登录永久挂起。
另外客户端每 ~20s 发单字节 0x00 心跳，服务端必须回一个字节让 addResp 重置超时。
"""
import asyncio
import json
import struct
import sys
import time
import traceback

import websockets

sys.path.insert(0, '/opt/privsrv')
import store   # noqa: E402  共享数据层（当前用户/动态/蓝V名单）
import review  # noqa: E402  头像审核队列（上传/通过/拒绝）
try:
    import features   # noqa: E402  统一功能层（社交/内容/编辑器/商城）
except Exception as _fe:
    features = None
    print('  [warn] features import failed:', _fe, flush=True)
from server import bon_encode, lz4_xor_encode   # noqa: E402

LOG = '/opt/privsrv/logs/agent.log'


def log(*a):
    line = time.strftime('%Y-%m-%dT%H:%M:%S') + ' ' + ' '.join(str(x) for x in a)
    try:
        with open(LOG, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass
    print(line, flush=True)


# ---------------- lx 解码 ----------------
def unlx_key(b):
    return (((b[2] >> 6 & 1) << 7) | ((b[2] >> 4 & 1) << 6) | ((b[2] >> 2 & 1) << 5) |
            ((b[2] & 1) << 4) | ((b[3] >> 6 & 1) << 3) | ((b[3] >> 4 & 1) << 2) |
            ((b[3] >> 2 & 1) << 1) | (b[3] & 1))


def inflate_raw(b):
    try:
        import lz4.frame
        d = bytearray(b[:100])
        k = unlx_key(b)
        for i in range(len(d) - 1, 1, -1):
            d[i] ^= k
        d[0], d[1], d[2], d[3] = 4, 34, 77, 24
        return lz4.frame.decompress(bytes(d) + b[100:])
    except Exception:
        return None


def readable(b):
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in b[:300])


# ---------------- bon 解码 ----------------
def r7(b, p):
    v, sh = 0, 0
    while True:
        c = b[p]
        p += 1
        v |= (c & 0x7f) << sh
        if not (c & 0x80):
            return v, p
        sh += 7


def _bd(b, p, strs):
    t = b[p]; p += 1
    if t == 0: return None, p
    if t == 1: return struct.unpack_from('<i', b, p)[0], p + 4
    if t == 2: return struct.unpack_from('<q', b, p)[0], p + 8
    if t == 4: return struct.unpack_from('<d', b, p)[0], p + 8
    if t == 5:
        n, p = r7(b, p); s = b[p:p + n].decode('utf8', 'replace'); p += n
        strs.append(s); return s, p
    if t == 6: return bool(b[p]), p + 1
    if t == 7:
        n, p = r7(b, p); d = b[p:p + n]; p += n
        # 0x07 二进制块有两种来源：
        #   * 服务端回包的 body（内部就是嵌套 bon）-> 解成 dict/list
        #   * 客户端上传的 PNG content（原始字节）-> 必须原样保留，否则图片数据丢失
        # 用「是否消费完整块」区分，避免把 PNG 首字节 0x89 误当成 bon 类型。
        try:
            inner, q = _bd(d, 0, [])
            if q == len(d) and isinstance(inner, (dict, list)):
                return inner, p
        except Exception:
            pass
        return bytes(d), p
    if t == 8:
        n, p = r7(b, p); o = {}
        for _ in range(n):
            k, p = _bd(b, p, strs); v, p = _bd(b, p, strs); o[str(k)] = v
        return o, p
    if t == 9:
        n, p = r7(b, p); a = []
        for _ in range(n):
            v, p = _bd(b, p, strs); a.append(v)
        return a, p
    if t == 0x63:
        i, p = r7(b, p)
        return (strs[i] if i < len(strs) else '<ref%d>' % i), p
    return '<type 0x%02x>' % t, p


def bon_decode(b):
    return _bd(b, 0, [])[0]


# ---------------- 动态配置数据 ----------------
BANNERS = [
    {'imgUrl': '/uploads/cover/demo1.png', 'jumpUrl': '', 'title': '像素冒险',
     'jumpType': 0, 'id': 1},
    {'imgUrl': '/uploads/cover/demo4.png', 'jumpUrl': '', 'title': '方块生存',
     'jumpType': 0, 'id': 2},
    {'imgUrl': '/uploads/cover/demo5.png', 'jumpUrl': '', 'title': '弹幕射击',
     'jumpType': 0, 'id': 3},
]


GAMES = [
    {'id': '1001', 'name': '像素冒险',   'iconTextureName': 'demo1.png', 'rank': 1,
     'thumbCnt': 128, 'collectionCnt': 42, 'playCnt': 3580, 'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1002', 'name': '方块生存',   'iconTextureName': 'demo4.png', 'rank': 2,
     'thumbCnt': 96,  'collectionCnt': 31, 'playCnt': 2410, 'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1003', 'name': '弹幕射击',   'iconTextureName': 'demo5.png', 'rank': 3,
     'thumbCnt': 75,  'collectionCnt': 20, 'playCnt': 1890, 'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1004', 'name': '迷宫探秘',   'iconTextureName': 'demo1.png', 'rank': 4,
     'thumbCnt': 63,  'collectionCnt': 18, 'playCnt': 1520, 'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1005', 'name': '塔防物语',   'iconTextureName': 'demo4.png', 'rank': 5,
     'thumbCnt': 51,  'collectionCnt': 12, 'playCnt': 1203, 'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1006', 'name': '跑酷达人',   'iconTextureName': 'demo5.png', 'rank': 6,
     'thumbCnt': 44,  'collectionCnt': 9,  'playCnt': 980,  'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1007', 'name': '星空战机',   'iconTextureName': 'demo1.png', 'rank': 7,
     'thumbCnt': 40,  'collectionCnt': 8,  'playCnt': 860,  'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1008', 'name': '农场物语',   'iconTextureName': 'demo4.png', 'rank': 8,
     'thumbCnt': 36,  'collectionCnt': 7,  'playCnt': 742,  'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1009', 'name': '节奏大师',   'iconTextureName': 'demo5.png', 'rank': 9,
     'thumbCnt': 33,  'collectionCnt': 6,  'playCnt': 655,  'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1010', 'name': '解谜之门',   'iconTextureName': 'demo1.png', 'rank': 10,
     'thumbCnt': 29,  'collectionCnt': 5,  'playCnt': 533,  'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1011', 'name': '赛车狂飙',   'iconTextureName': 'demo4.png', 'rank': 11,
     'thumbCnt': 25,  'collectionCnt': 4,  'playCnt': 421,  'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
    {'id': '1012', 'name': '海底探险',   'iconTextureName': 'demo5.png', 'rank': 12,
     'thumbCnt': 20,  'collectionCnt': 3,  'playCnt': 310,  'hurryCnt': 0,
     'advert': '', 'openCreativeGame': False, 'lastPublishTime': 0},
]
GAME_IDS = [g['id'] for g in GAMES]


# ---- ABTest 配置：所有 ABTestType 都要有对象，避免 undefined.isOpen 崩溃 ----
# isOpen=False 且 targetPlan!=0 -> getABTestValue 立刻 return，不碰 role.createAt / role.aBTest
# 目标值让 isPlanATest 全部返回 False（走 B 方案），界面最稳、子 tab 齐全。
_AB_TARGET = {
    'recommendAB':          202,   # recommendGame_B
    'chosenCntAB':          302,   # aBTest3_B
    'chosenPagePosAB':      402,   # aBTest4_B
    'gameTypeAB':           502,   # aBTest5_B
    'discoverForNewUserAB': 602,   # aBTest6_B  -> 显示 4 个子 tab + 搜索框
    'noChosen':             702,   # aBTest7_B
    'onlyChosen':           802,   # aBTest8_B
}
ABTEST_SWITCHS = {
    k: {'isOpen': False, 'targetPlan': v, 'newUserStartTime': 0}
    for k, v in _AB_TARGET.items()
}


# ======================= 蓝V / 官方账号（服务端下发）=======================
# 客户端 DynamicMng.isGmPlayer():
#   (this.map.get("GmPlayerIds") || []).indexOf(role.id) >= 0
# 名单不再硬编码：由后台(admin.py)把用户 authed 置 true，服务端动态生成。
def gm_ids():
    try:
        return store.gm_ids()
    except Exception:
        return []


GM_IDS = []   # 兼容旧引用；实际值一律走 gm_ids()

# ======================= 教程：全量完成标记 =======================
# roleLogin(): F.default.Ins.completeTaskIds = e.role.completeTaskIds; F.default.Ins.init()
# GuideMng.init(): 若 !isComplete(EditWorld) 就 push 1..EditWorld 并 save()；
# 最后按 isComplete(CreateGame/CreateWorld/EditWorld) 决定放哪段教程。
# 服务端给空数组 => 每次登录从头放，且编辑器初始化会再触发一次 => 「同一轮对话放两遍」。
# 全部 ID 标记完成 => init() 直接 return，教程不再放，game_saveguide 也不再发。
ALL_GUIDE_IDS = [1, 2, 3, 4, 1001, 1002, 1003, 1004, 1101, 1102]

# ======================= 动态（社区测试数据）=======================
_T0 = int(time.time() * 1000)

def make_talk(title, text, hours=0, up=0):
    """构造符合 TalkData(a(0)/a(1)/a(2)) schema 的一条动态。
    simpleContent 是 a(0) 标量直传：TalkCell.setData 读 o.text / o.specialSection。
    status 用 ManReviewStatus.success=1（0=noPublish 会被过滤）。"""
    ts = _T0 - hours * 3600000
    _cu = None
    try:
        _cu = store.current_user()
    except Exception:
        _cu = None
    _cu = _cu if isinstance(_cu, dict) else {}
    _uid = str(_cu.get('userId', '1000111'))
    try:
        _pid = int(_uid)
    except Exception:
        _pid = 1000111
    # uId 占位：add_talk 会强制覆盖成 talkId(hash)，这里给作者 uid 仅兼容旧调用
    return {
        'uId': _uid, 'playerId': _pid, 'userLevel': _cu.get('level', 99),
        'userImg': '', 'userName': str(_cu.get('userName') or '玩家'),
        'userIntro': str(_cu.get('userIntro') or ''),
        'talkType': 'trends',
        'title': title,
        'simpleContent': {'text': text},
        'content': {},
        'upCnt': up, 'reportCnt': 0, 'commentsCnt': 0, 'commentsCntSum': 0,
        'isTop': False, 'isUp': False, 'isDown': False,
        'topComment': {}, 'comments': [],
        'status': 1, 'offReason': {},
        'createStamp': ts, 'newCommentStamp': ts, 'upStamp': ts,
        'collectionCntSum': 0,
    }

# 演示动态已移除：全部动态由 store(data/talks.json) 持久化，后台可增删改
TALKS = []

# 动态统一由 store 持久化到 data/talks.json（后台 admin 可增删改，重启不丢）
def save_user_talks():
    pass  # 兼容旧调用；写入由 store.add_talk 完成


def all_talks():
    try:
        return store.load_talks()[::-1]   # 最新在前
    except Exception:
        return []


def login_payload(now):
    """构造符合 Game_RLogin schema 的完整回包。

    客户端: SendCmdAsync({cmd: game_login}, Game_RLogin)
         -> DecodeMsg(decBody, Game_RLogin) -> new Game_RLogin().setValue(decBody)
    setValue 只认 schema 注册字段，且按类型解析：
      se(1, Class)  -> 单对象，递归 setValue   (role / roleGameConf / offLineChangeMsg)
      se(2, Class)  -> 对象数组，逐项 setValue  (newGameDatas / followGameDatas / saleSummarys...)
      se(2)         -> 数组                    (hotGameIdList / gameSlotUnlockLvls ...)
      se(5)         -> Map，逐 key m.set(k, v) (dynamicConfig)
      se(0)         -> 标量                    (newMsgCnt / canObtainTTCoin ...)
    GDRole 里 a(4) 是 Date（传毫秒时间戳）、a(3) 是 Map（传对象）、a(1) 是嵌套对象。
    """
    role = {
        'id': 1000111, 'uId': 1000111, 'sId': 1000111, 'uKey': '',
        'userInfo': {},                      # a(1) 嵌套对象
        'coin': 8888, 'diamond': 100, 'creditScore': 3,
        'reviewCreditScore': 100, 'examScore': 100,   # 发布商品需 examScore>=100
        'publishGameTimes': 0, 'publishGoodsTimes': 0,
        'creditTime': now,                  # a(4) Date
        'creditMsgList': [],
        'goodsIds': [], 'myGameMaxCnt': 10, 'myGoodsMaxCnt': 10,
        'authed': False, 'creatorVersion': '', 'userName': '玩家',
        'exp': 0, 'level': 99, 'userImg': '', 'userIntro': '',
        # ★ UnlockPublishLvl=5：level=1 会弹「等级5解锁」，卡死发动态/发布作品
        'gameIncId': 0, 'worldIncId': 0, 'variableIncId': 0, 'customColorIncId': 0,
        'games': [], 'collectionGames': [], 'worlds': [], 'variables': [],
        'fansCount': 0, 'bindRoleCode': '', 'beBindList': [], 'channel': 'hortor',
        'customActorGroups': [], 'customColors': [], 'guideVersion': '0.8.10',
        # ★ 教程全量完成：根治「同一轮对话放两遍」+ 每次登录重放
        'completeTaskIds': list(ALL_GUIDE_IDS), 'follows': [],
        'createAt': now - 86400000 * 30,    # a(4) Date：30天前，避免"新用户"分支
        'collectionGoods': [], 'collectionTalks': [],
        'newUserImg': '', 'userImgTime': now, 'newUserImgReviewStatus': 0,
        'offReason': {},                    # a(1) 嵌套对象
        'addCoinCounters': {},              # a(3) Map
        'aBTest': {},                       # a(3) Map
    }
    role_game_conf = {
        'tileConfIds': [], 'actorConfIds': [], 'deviceConfIds': [],
        'propConfIds': [], 'weaponConfIds': [], 'bulletConfIds': [],
    }
    # dynamicConfig (se(5) Map) 一次性喂给 DynamicMng.Ins.init()，
    # 这样 loadOne() 直接命中，不会再发 game_getonedynamicconfig，也不会拿到 Promise。
    dyn = {
        'abTestSwitchs': ABTEST_SWITCHS,
        'DisableFunction': {},          # isDisable 读 o[channel]
        'InspectVersionData': {},       # isInspectVersion 读 e[channel]
        'GameSwitchs': [], 'GameChosenIds': GAME_IDS, 'GameTypeSwitch': {},
        'GameTags': [], 'GiftRank': {}, 'GamePotential': {}, 'GmPlayerIds': gm_ids(),
        'ViolationsNames': {}, 'IpGameIds': [], 'IpGoodsIds': [],
        'ChosenGoodsIds': [], 'bbsBanner': {'list': BANNERS, 'total': len(BANNERS)},
        'bannerConf': {'isOpen': False, 'bannerType': 0, 'hasChosen': False,
                       'lvLimit': 0, 'fansLimit': 0, 'list': [], 'banners': []},
        'GameTagSwitch': {'isOpen': False},
        'GuideOnLineTime': {'guideOnlineTime': 0, 'onlineTime': 0, 'openGuide': False},
        'Notice': {'list': [], 'total': 0},
    }
    # ===== 多用户：把「当前会话账号」的字段覆盖到回包（try 兜底，绝不白屏）=====
    # 后台改 G币(coin)/钻石/等级/昵称/简介/蓝V(authed) 后，客户端 game_login 立即读到。
    try:
        dyn['GmPlayerIds'] = gm_ids()
    except Exception:
        pass
    try:
        u = store.current_user()
        if isinstance(u, dict):
            try:
                rid = int(u.get('userId', 1000111))
            except Exception:
                rid = 1000111
            role['id'] = rid; role['uId'] = rid; role['sId'] = rid
            # ★ 我的游戏列表：动态返回该用户在 ft.editor[uid].gamedata 下的存档 id。
            # 否则客户端 gameMng.gameIds 恒为空 -> 重进 APP 后「我的作品」全部丢失。
            try:
                _ft = features.load_feat()
                _ed = _ft.get('editor', {}).get(str(rid), {})
                role['games'] = list(_ed.get('gamedata', {}).keys())
            except Exception:
                pass
            for _k in ('coin', 'diamond', 'level', 'exp', 'userName',
                       'userIntro', 'userImg', 'authed'):
                if _k in u and u[_k] is not None:
                    role[_k] = u[_k]
            # ★ 信誉分：后台扣分/加分后，重新登录即生效（否则 CreditMng.Ins.credit 恒为默认值，
            #    点赞/收藏/举报/发布等「credit<=2 不可操作」的限制永远不触发）。
            #    语义：0~3 等级点（3=满信誉全绿，2/1=缺信誉，0=封号），客户端按此渲染叶子。
            try:
                _cs = _ft.get('credit', {}).get(str(rid), {})
                role['creditScore'] = max(0, min(3, features.as_int(_cs.get('score'), 3)))
                role['creditMsgList'] = _cs.get('list', [])[:20]
            except Exception:
                pass
            # 头像审核结果下发：0=无 / 1=通过 / 2=审核中 / 3=拒绝
            # 后台点「通过」后，客户端重新登录即读到 success + 新 userImg。
            try:
                _rs = u.get('imgReviewStatus', 0)
                role['newUserImgReviewStatus'] = _rs if _rs in (0, 1, 2, 3) else 0
                role['newUserImg'] = str(u.get('newUserImg') or '')
            except Exception:
                pass
    except Exception:
        pass
    return {
        'role': role,                       # se(1, GDRole)
        'dynamicConfig': dyn,               # se(5) Map
        'roleGameConf': role_game_conf,     # se(1, GDRoleGameConf)
        'offLineChangeMsg': {},             # se(1, OffLineChangeMsg) -> incExp 默认 0
        'saleSummarys': [], 'gameSaleSummarys': [], 'adSummarys': [], 'rebornSummarys': [],
        'unlockGameRewards': [], 'unlockGoodsRewards': [],
        'gameSlotUnlockLvls': [], 'goodsSlotUnlockLvls': [],
        'hotGameIdList': GAME_IDS,
        'newGameDatas': GAMES,              # se(2, GameCellData) -> DiscoverMng.freshGames
        'followGameDatas': [],
        'newMsgCnt': 0, 'newAggregateMsgCnt': 0, 'newFansCnt': 0, 'newCommentCnt': 0,
        'canObtainTTCoin': False, 'customActorGroups': [],
        'addCoinByAdvertCnt': 0, 'addCoinByAdvertLimit': 0, 'addCoinByAdvertReset': 0,
        'collectionGoods': [], 'giftCfgVersion': '',
        # ★ 正式账号标记：roleLogin() 里
        #   socialBinded = e.userPlatforms && e.userPlatforms.length > 0
        #   isVisitor() = isApp() && !socialBinded
        # 非空数组 => 非游客 => 发布作品/动态/改资料等功能全部解禁，
        # 且不再弹「请先绑定账号」。se(2) 数组，元素为平台字符串。
        'userPlatforms': ['app-mobile'],
        # 会话冗余字段（schema 未注册会被 setValue 忽略，但保留兼容其它读取路径）
        'code': 0, 'msg': 'ok', 'channel': 'hortor', 'time': now,
        'roleId': 1000111, 'userId': '1000111', 'userName': 'privsrv',
        'isRestore': 0, 'serverTime': now, 'sessionId': str(now),
        'gameId': 'GameCreator-app', 'data': {}, 'list': [],
    }


def config_for_id(cid):
    """game_getonedynamicconfig 按 id 返回对应配置内容。"""
    if cid == 'Notice':
        return {'list': [
            {'id': 1, 'title': '欢迎回到创游编辑器',
             'content': '服务器已停服，本内容仅供怀念。',
             'type': 1, 'status': 1, 'sort': 1,
             'startTime': 0, 'endTime': 0},
        ], 'total': 1}
    if cid == 'bbsBanner':
        return {'list': BANNERS, 'total': len(BANNERS)}
    if cid == 'abTestSwitchs':
        # getABTestValue(e) 用字符串 key 取: (map.get("abTestSwitchs") || ...)[e]
        # 每个 ABTestType 都要有 {isOpen, targetPlan, newUserStartTime}，
        # 否则 t.isOpen 抛异常 -> DiscoverPage.onLoad 被 Cocos 吞掉 -> 内容区空白。
        # targetPlan 给非 0 让 getABTestValue 直接 return，绕开 role.createAt/aBTest。
        return ABTEST_SWITCHS
    if cid == 'GuideOnLineTime':
        return {'guideOnlineTime': 0, 'onlineTime': 0, 'openGuide': False}
    # ===== 首页内容配置：DiscoverSubPage.refresh() 逐个 loadOne 消费 =====
    if cid == 'bannerConf':
        # isOpen=False 先不触发 BbsBanner 远程图片渲染，避免半初始化崩溃
        return {'isOpen': False, 'bannerType': 0, 'hasChosen': False,
                'lvLimit': 0, 'fansLimit': 0, 'list': [], 'banners': []}
    if cid == 'GameTagSwitch':
        return {'isOpen': True}
    if cid == 'GameChosenIds':
        return GAME_IDS
    if cid == 'GameTypeSwitch':
        return {}
    if cid == 'GameTags':
        return []
    if cid == 'GiftRank':
        return {}
    if cid == 'DisableFunction':
        return {}
    if cid == 'InspectVersionData':
        return {}
    if cid == 'GameSwitchs':
        return []
    if cid == 'GamePotential':
        return {}
    if cid in ('IpGameIds', 'IpGoodsIds', 'ChosenGoodsIds'):
        return []
    if cid == 'ViolationsNames':
        return {}
    if cid == 'GmPlayerIds':
        # 蓝V名单由后台用户 authed 字段动态生成，服务端下发
        return gm_ids()
    # 兜底：返回空对象，避免客户端解析崩溃
    return {'list': [], 'total': 0}


# ---------------- 头像上传 / 审核（任务：后台审核头像）----------------
def req_param(req, name, default=None):
    """从 WS 请求的多个层级取参数（兼容客户端把 params 放顶层或 body/data）。"""
    srcs = [req]
    for k in ('body', 'params', 'data'):
        v = req.get(k)
        if isinstance(v, dict):
            srcs.append(v)
    for s in srcs:
        if name in s and s[name] not in (None, ''):
            return s[name]
    return default


def to_png_bytes(v):
    """把 bon 解码后的 content 还原成 PNG 字节。"""
    import base64 as _b64
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, list):
        try:
            return bytes(int(x) & 255 for x in v)
        except Exception:
            return b''
    if isinstance(v, str):
        try:
            return _b64.b64decode(v)
        except Exception:
            pass
        try:
            return v.encode('latin1')
        except Exception:
            return b''
    return b''


def save_upload_png(content):
    """把上传的 PNG 落到 /opt/privsrv/uploads/cover/，返回客户端可加载的 URL。
    nginx: /GameCreator-byte/ 与 /uploads/ 均指向 /opt/privsrv/uploads/。"""
    import os as _os, uuid as _uuid
    raw = to_png_bytes(content)
    if not raw:
        return None
    # 客户端 HeadIconMng.isCdnPng() 只认含 'pixel/' 的名字，否则显示内置默认头像；
    # downLoadPng 拼 fileCDN(=/GameCreator-byte/) + 名字，nginx alias 到 uploads/cover/。
    d = '/opt/privsrv/uploads/cover/pixel'
    _os.makedirs(d, exist_ok=True)
    name = 'avatar_%s.png' % _uuid.uuid4().hex[:12]
    with open(_os.path.join(d, name), 'wb') as f:
        f.write(raw)
    return 'pixel/' + name


def make_reply(req):
    if not isinstance(req, dict):
        return None, None
    cmd = req.get('cmd') or 'game_login'
    seq = int(req.get('seq') or 0)
    now = int(time.time() * 1000)
    # 业务响应体：data 承载具体配置，list 作为冗余承载，兼容不同客户端取值方式
    if cmd == 'game_getonedynamicconfig':
        cid = (req.get('body') or {}).get('id', '')
        cfg = config_for_id(cid)
        payload = {'dynamicConfig': cfg,
                   'data': cfg, 'list': cfg.get('list', cfg) if isinstance(cfg, dict) else cfg,
                   'total': cfg.get('total', 0) if isinstance(cfg, dict) else 0,
                   'id': cid, 'code': 0, 'msg': 'ok'}
    elif cmd == 'game_getgiftdyncfg':
        payload = {'data': {'giftList': [], 'list': []}, 'list': [], 'code': 0, 'msg': 'ok'}
    elif cmd == 'game_saveguide':
        # Game_RSaveGuide = class extends re {}（空 schema），回空对象即可。
        # 教程已由 role.completeTaskIds 全量完成，正常不会再走到这里。
        payload = {}
    elif cmd in ('game_createtalk', 'game_createofficialtalk'):
        # 客户端 publishTalk() -> SendCmdAsync(..., Game_RCreateTalk)
        # Game_RCreateTalk: code(a0) / sensitiveWords(a2) / talkData(a1 TalkData)
        # 成功后客户端把回包 talkData unshift 进本地列表 -> 必须带完整 TalkData。
        _b = req.get('body') or {}
        # 客户端 SendCmdAsync({cmd, params}) 可能把 params 直接摊在 body，
        # 也可能包一层 body.params，两种都兼容。
        params = _b.get('params') if isinstance(_b.get('params'), dict) else _b
        if not isinstance(params, dict): params = {}
        sc = params.get('simpleContent')
        text = sc.get('text', '') if isinstance(sc, dict) else ''
        td = make_talk(str(params.get('title') or '')[:60] or '我的动态',
                       str(text or '')[:500] or '（无正文）', 0, 0)
        td['content'] = params.get('content') if isinstance(params.get('content'), dict) else {}
        # 动态归属当前账号 + 走共享层持久化（后台可删改）
        try:
            cu = store.current_user()
            if isinstance(cu, dict):
                # 不要覆写 uId：它是动态唯一主键，由 store.add_talk 统一赋 talkId
                try:
                    td['playerId'] = int(cu.get('userId', td['playerId']))
                except Exception:
                    pass
                td['userName'] = str(cu.get('userName') or td['userName'])
                td['userIntro'] = str(cu.get('userIntro') or '')
                td['userLevel'] = cu.get('level', td['userLevel'])
        except Exception:
            pass
        td = store.add_talk(td)
        print('  [talk] CREATE title=%r total=%d' % (td['title'], len(store.load_talks())), flush=True)
        payload = {'code': 0, 'msg': 'ok', 'success': True, 'result': True,
                   'sensitiveWords': [], 'talkData': td,
                   'data': td, 'list': [], 'id': td.get('uId', '')}
    elif cmd in ('game_loadtalk', 'game_loadowntalk', 'game_loadtalkbyidlist',
                 'game_searchtalk'):
        # Game_RLoadTalk = Wo: startMember(se0) / talkList(se2 TalkData)
        payload = {'talkList': all_talks(), 'startMember': '',
                   'total': len(all_talks()), 'code': 0, 'msg': 'ok',
                   'data': {'talkList': all_talks()}, 'list': all_talks()}
    elif cmd == 'game_uploadimage':
        # 客户端 Util.uploadPng：发 Game_UploadImage 带 PNG 二进制 content，
        # 期待 Game_RUploadImage = { url, reason }。reason 必须为空才算上传成功。
        content = req_param(req, 'content')
        url = save_upload_png(content) if content is not None else None
        if not url:
            payload = {'code': -1, 'reason': '图片数据为空', 'url': '',
                       'msg': 'upload failed', 'data': {}, 'list': []}
        else:
            payload = {'code': 0, 'reason': '', 'url': url, 'msg': 'ok',
                       'data': {'url': url, 'reason': ''}, 'list': []}
            log('  UPLOADIMG ->', url)
    elif cmd == 'game_updateuserimg':
        # 客户端把 role.newUserImgReviewStatus 硬编码为「审核中」，
        # 服务端在此登记待审核记录；后台通过后 game_login 会下发 success + 新头像。
        url = str(req_param(req, 'newUserImg', '') or '')
        _db = store.load_db()
        _cu = store.current_user()
        _uid = str(_cu.get('userId')) if isinstance(_cu, dict) else (
            _db.get('currentUid') or _db.get('lastUser') or '')
        _r = review.add_pending(_db, _uid, url) if (_uid and url) else None
        store.save_db(_db)
        log('  UPDATEUSERIMG uid=%s url=%s rid=%s auto=%s' %
            (_uid, url, (_r or {}).get('rid'), review.auto_enabled()))
        payload = {'code': 0, 'msg': 'ok', 'result': True, 'success': True,
                   'newUserImg': url, 'status': review.INREVIEW,
                   'data': {'newUserImg': url}, 'list': []}
    elif cmd == 'game_getneedreviewimagelist':
        # Game_RGetNeedReviewImageList = Ft: needImageList(se2)。空列表=无待审图
        payload = {'needImageList': [], 'code': 0, 'msg': 'ok',
                   'data': {'needImageList': []}, 'list': []}
    elif cmd == 'game_getuserdetailmsg':
        # Game_RGetUserDetailMsg = Io: userDetailMsg(se1 UserDetailMsg)
        # ★ 按请求 id 返回「目标用户」的资料。客户端点别人主页时 body 带 {id: 目标uid}，
        #   旧实现永远用 current_user()，导致进任何人的主页都显示自己的信息、只是 ID 不同。
        tid = ''
        try:
            if isinstance(req, dict):
                for _src in (req, req.get('body'), req.get('params'), req.get('data')):
                    if isinstance(_src, dict) and _src.get('id') not in (None, ''):
                        _v = str(_src['id'])
                        # 详情页拿不到作者时会带 id=0；归一化为空 -> 回退当前用户，
                        # 避免显示成「玩家0」并把粉丝/关注数串成自己的。
                        tid = '' if _v in ('0', 'None') else _v
                        break
        except Exception:
            pass
        users, cu = {}, {}
        try:
            users = store.load_db().get('users', {}) or {}
        except Exception:
            pass
        try:
            _cu = store.current_user()
            cu = _cu if isinstance(_cu, dict) else {}
        except Exception:
            pass
        u = users.get(tid) or {}
        if not u and not tid:
            u = cu
        try:
            pid = int(tid or u.get('userId') or cu.get('userId') or 1000001)
        except Exception:
            pid = 1000001
        try:
            _lv = int(u.get('level') or 1)
        except Exception:
            _lv = 1
        ft = {}
        try:
            ft = features.load_feat() if features else {}
        except Exception:
            ft = {}
        my = str(cu.get('userId') or '')
        my_follows = [str(x) for x in (ft.get('follows', {}).get(my, []) or [])]
        fans = ft.get('fans', {}).get(str(pid), []) or []
        follows = ft.get('follows', {}).get(str(pid), []) or []
        detail = features.data_obj('UserDetailMsg', **{
            'playerId': pid,
            'userName': str(u.get('userName') or ('玩家' + str(pid)[-4:])),
            'userImg': str(u.get('userImg') or ''),
            'userIntro': str(u.get('userIntro') or u.get('sign') or ''),
            'level': _lv,
            'isFollow': str(pid) in my_follows,
            'fansCount': len(fans),
            'followCount': len(follows),
            'goodsIds': [],
            'gameDatas': [],
        })
        # 兼容字段（UserDetailMsg 未注册，客户端 setValue 会跳过；调试/后台可读）
        detail['id'] = pid
        detail['uId'] = str(pid)
        payload = {'userDetailMsg': detail, 'code': 0, 'msg': 'ok',
                   'data': detail, 'list': []}
    elif cmd == 'game_getusersimplemsg':
        # Game_RGetUserSimpleMsg = bo: userSimpleMsgList(se2 UserSimpleMsg)
        sm = {'id': 1000111, 'userName': '玩家', 'userImg': '',
              'coin': 8888, 'diamond': 100, 'level': 99,
              'creditScore': 3, 'isFollow': False, 'authed': False,
              'fansCount': 0, 'followsCount': 0}
        try:
            cu = store.current_user()
            if isinstance(cu, dict):
                try:
                    sm['id'] = int(cu.get('userId', sm['id']))
                except Exception:
                    pass
                sm['userName'] = str(cu.get('userName') or sm['userName'])
                sm['coin'] = cu.get('coin', sm['coin'])
                sm['diamond'] = cu.get('diamond', sm['diamond'])
                sm['level'] = cu.get('level', sm['level'])
                sm['authed'] = bool(cu.get('authed', False))
                # 信誉分读真实值（后台加/扣后即时反映），0~3 等级点
                try:
                    _ft = features.load_feat() if features else {}
                    _cid = str(cu.get('userId') or sm['id'])
                    sm['creditScore'] = max(0, min(3, features.as_int(_ft.get('credit', {}).get(_cid, {}).get('score'), 3)))
                except Exception:
                    pass
        except Exception:
            pass
        payload = {'userSimpleMsgList': [sm], 'code': 0, 'msg': 'ok',
                   'data': {'userSimpleMsgList': [sm]}, 'list': [sm]}
    elif cmd == 'game_getusercreditmsg':
        # 信誉明细（CreditScene.loadData 读 userCreditMsgList / creditScoreRecoverProcess）。
        # 客户端 CreditMng.loadData 只在首次进入时拉一次，故此处返回当前用户的真实明细。
        _list = []
        _process = 0
        try:
            _cu = store.current_user()
            _uid = str(_cu.get('userId')) if isinstance(_cu, dict) else None
            if _uid:
                _ft = features.load_feat() if features else {}
                _cs = _ft.get('credit', {}).get(_uid, {})
                _list = _cs.get('list', [])[:50]
                _process = features.as_int(_cs.get('recoverProcess'), 0)
        except Exception:
            pass
        payload = {'userCreditMsgList': _list, 'creditMsgList': _list,
                   'creditScoreRecoverProcess': _process, 'code': 0, 'msg': 'ok',
                   'data': {'userCreditMsgList': _list}, 'list': _list}
    elif cmd in ('game_gethomepagegamedata', 'game_gethomepagenewgames',
                 'game_gethomepagerecommendsgames', 'game_gethomepagefollowusergames'):
        # GameMng.loadGames(ids) -> Game_RGetHomepageGameData.gameDatas (GameCellData[])
        # 客户端不按 ids 过滤，直接采用回包里的 gameDatas
        payload = {'gameDatas': GAMES, 'data': {'gameDatas': GAMES},
                   'list': GAMES, 'total': len(GAMES), 'startMember': '',
                   'code': 0, 'msg': 'ok'}
    elif cmd == 'game_login':
        # ★ 关键：按 Game_RLogin schema 返回完整字段，原版首页才有数据可渲染
        payload = login_payload(now)
    else:
        # 其它 cmd：先交给统一功能层分发（社交/内容/编辑器/商城）。
        # 未命中返回 None -> 走原兜底，已跑通的 20 个分支完全不受影响。
        _ext = None
        if features is not None:
            try:
                _ext = features.dispatch(cmd, req)
            except Exception as _fe:
                log('  FEATURE_ERR', cmd, str(_fe))
        if _ext is not None:
            payload = _ext
        else:
            # 未知指令：保持会话字段
            payload = {
                'code': 0, 'msg': 'ok', 'channel': 'hortor', 'time': now,
                'roleId': 1000111, 'userId': '1000111', 'userName': 'privsrv',
                'isRestore': 0, 'serverTime': now, 'sessionId': str(now),
                'gameId': 'GameCreator-app', 'data': {}, 'list': [],
            }
    # ★★ 关键（来自客户端 WC_doReceive 源码）：
    #   n.decBody = n.body && bon.decode(n.body);   <- 直接对 body 做【裸 bon】解码
    #   这一行在 try 最开头，若 body 不是合法 bon 会抛异常 -> 整个 doReceive 进 catch，
    #   后面的 `if (n.resp === i.seq) i.resolve(n)` 不会执行 -> sendAsync Promise 永远 pending
    #   -> App 卡在 game_login，首页内容请求发不出去（首页空白）。
    #   因此 body 必须是【裸 bon(payload) 字节】，绝不能是 lz4 流（那是 HTTP 登录的套路）。
    # 补强已实现分支：给 game_login / game_loadtalk 等附加互动数据（内部 try 保护）
    if features is not None:
        try:
            payload = features.post_process_all(cmd, payload, req)
        except Exception as _fe:
            log('  POSTPROC_ERR', cmd, str(_fe))
    body_raw = bon_encode(payload)   # 裸 bon 字节，客户端 bon.decode 可直接解
    msg = {
        'ack': seq,        # 确认客户端发出去的包（_sndQueue.confirm）
        'resp': seq,       # ★关键：让 doReceive 里 sendAsync 的 Promise resolve（须严格 === 请求 seq）
        'cmd': cmd,        # 非 _sys/*，才会进 default -> doReceive
        'body': body_raw,  # 裸 bon 字节（客户端 bon.decode(n.body) 得到 payload）
        'time': now,
        'code': 0,         # doReceive: n.code = ~~n.code，负值会进 Error 状态
        # seq 故意不给（保持 0），客户端心跳就会走单字节 0x00
        # 冗余：业务字段同时放在外层，兼容「直接读 msg.data/list」的取值方式
        'data': payload.get('data', {}),
        'list': payload.get('list', []),
        'total': payload.get('total', 0),
        'id': payload.get('id', ''),
        'roleId': payload.get('roleId', 1000111),
        'userId': payload.get('userId', '1000111'),
        'userName': payload.get('userName', 'privsrv'),
        'sessionId': payload.get('sessionId', str(now)),
        'serverTime': payload.get('serverTime', now),
    }
    return lz4_xor_encode(bon_encode(msg)), msg


async def handler(ws, *args):
    try:
        req = getattr(ws, 'request', None)
        path = getattr(req, 'path', '?') if req else '?'
        hdr = dict(req.headers) if req is not None and hasattr(req, 'headers') else {}
    except Exception:
        path, hdr = '?', {}
    log('CONNECT', path, ws.remote_address, json.dumps(hdr, ensure_ascii=False)[:300])
    try:
        async for msg in ws:
            if isinstance(msg, (bytes, bytearray)):
                b = bytes(msg)
                log('RECV bin', len(b), b[:120].hex())
                # 单字节 0x00 = 客户端心跳；addResp 开头会 resetConnectionTimeout，
                # 只要回任意一个字节即可保活，且 <=1 会直接 return，不触发业务分发。
                if len(b) <= 1:
                    log('  PING -> PONG 0x00')
                    try:
                        await ws.send(b'\x00')
                    except Exception:
                        pass
                    continue
                raw = inflate_raw(b)
                reqobj = None
                if raw:
                    log('  INFLATE', len(raw), readable(raw))
                    try:
                        reqobj = bon_decode(raw)
                        log('  REQ', json.dumps(reqobj, ensure_ascii=False, default=str)[:500])
                    except Exception as e:
                        log('  BONERR', str(e))
                cmd = reqobj.get('cmd', '') if isinstance(reqobj, dict) else ''
                # 系统帧（_sys/ack 心跳确认等）：addResp 里直接 return，只需回一个字节保活
                if cmd.startswith('_sys/'):
                    log('  SYS', cmd, '-> PONG 0x00')
                    try:
                        await ws.send(b'\x00')
                    except Exception:
                        pass
                    continue
                frame, reply = make_reply(reqobj)
                if frame:
                    log('  SENT', json.dumps({k: (v if not isinstance(v, bytes) else '<bin %d B>' % len(v))
                                             for k, v in reply.items()}, ensure_ascii=False)[:400])
                    try:
                        await ws.send(frame)
                    except Exception as e:
                        log('  SENDERR', str(e))
            else:
                log('RECV txt', len(msg), str(msg)[:300])
                try:
                    await ws.send(b'\x00')
                except Exception:
                    pass
    except Exception:
        log('ERR', traceback.format_exc()[-400:].replace('\n', ' | '))
    log('CLOSE', path)


async def main():
    async with websockets.serve(handler, '127.0.0.1', 8765, max_size=None,
                                ping_interval=None):
        log('LISTEN 127.0.0.1:8765')
        await asyncio.Future()


if __name__ == '__main__':
    asyncio.run(main())
