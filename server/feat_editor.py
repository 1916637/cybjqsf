#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编辑器存档与作品发布：配置/世界/变量/颜色的 保存·读取·删除，作品发布与 CDN 上传。"""
import features as F

def cmd(req, default):
    return (req.get('_cmd') if isinstance(req, dict) else '') or F.param(req, 'cmd') or default

# 配置类型：命令关键字 -> feat.editor[uid] 下的子键
CONF_TYPES = {
    'roleactorconf': 'actor', 'rolebulletconf': 'bullet', 'roleweaponconf': 'weapon',
    'rolepropconf': 'prop', 'roletileconf': 'tile', 'roledeviceconf': 'device',
    'rolecreativeconf': 'creative', 'rolegamedata': 'gamedata',
    'worlddata': 'world', 'variable': 'variable', 'customcolors': 'colors',
    'actorgroups': 'groups', 'gameshop': 'shop', 'allvariable': 'variable',
    'allcustomcolors': 'colors',
}

def _conf_type(c):
    for k in sorted(CONF_TYPES, key=len, reverse=True):
        if k in c: return CONF_TYPES[k]
    return 'misc'

def _store(ft, u):
    return ft.setdefault('editor', {}).setdefault(str(u), {})

def _bucket(ft, u, c):
    return _store(ft, u).setdefault(_conf_type(c), {})

# ============================ 保存配置 ============================
@F.register(
    'game_saveroleactorconf', 'game_saverolebulletconf', 'game_saveroleweaponconf',
    'game_saverolepropconf', 'game_saveroletileconf',
    'game_saveroledeviceconf', 'game_saverolecreativeconf', 'game_saverolegamedata',
    'game_saveworlddata', 'game_savevariable', 'game_saveallvariable',
    'game_savecustomcolors', 'game_saveallcustomcolors', 'game_saveactorgroups',
    'game_savegameshop')
def h_save(req):
    c = cmd(req, 'game_saveroleactorconf')
    u = F.uid()
    cid = F.first(req, None, 'id', 'confId', 'gameId', 'groupName')
    data = F.first(req, None, 'data', 'conf', 'info', 'group', 'refDataList', 'datas', 'colors')
    if isinstance(data, (list, tuple)) and not isinstance(data, (str, bytes)):
        data = {'list': list(data)}
    if not isinstance(data, dict): data = {'value': data}
    def fn(ft, db):
        b = _bucket(ft, u, c)
        key = str(cid) if cid not in (None, '', 'null') else str(F.next_id(ft, 'conf'))
        rec = b.get(key, {})
        rec.update(data)
        rec['id'] = F.as_int(key, 0) if str(key).isdigit() else key
        rec['_stamp'] = F.now_ms()
        # 私服不做人工审核：游戏存档一律视为已发布（GameStatus.success=1），
        # 否则客户端 MyGameCell 按 status 显示「审核中」/「未发布」，且列表过滤后丢失。
        if _conf_type(c) == 'gamedata':
            rec['status'] = 1
        b[key] = rec
        return rec['id']
    rid = F.mutate(fn)
    ret = {}
    if 'allvariable' in c: ret['retVariableDatas'] = []
    if 'customcolors' in c: ret['colorDatas'] = []
    return F.payload(c, id=rid, confId=rid, gameId=F.as_int(cid, 0), **ret)

# ============================ 读取配置 ============================
@F.register(
    'game_getroleactorconf', 'game_getrolebulletconf', 'game_getroleweaponconf',
    'game_getrolepropconf', 'game_getroletileconf', 'game_getroledeviceconf',
    'game_getrolecreativeconf', 'game_getrolegamedata', 'game_getworlddata',
    'game_getvariable')
def h_getconf(req):
    c = cmd(req, 'game_getroleactorconf')
    u = F.uid()
    ids = F.as_list(F.first(req, None, 'ids', 'id'))
    ft = F.load_feat()
    b = _store(ft, u).get(_conf_type(c), {})
    if ids:
        items = [b[str(i)] for i in ids if str(i) in b]
    else:
        items = list(b.values())
    return F.payload(c, datas=items, confMap={str(k): v for k, v in b.items()})

@F.register(
    'game_getroleactorids', 'game_getrolebulletids', 'game_getroleweaponids',
    'game_getrolepropids', 'game_getroletileids', 'game_getroledeviceids',
    'game_getrolegameids', 'game_getworlddataids', 'game_getvariableids',
    'game_getgameshopids')
def h_getids(req):
    c = cmd(req, 'game_getroleactorids')
    ft = F.load_feat(); u = F.uid()
    b = _store(ft, u).get(_conf_type(c), {})
    return F.payload(c, ids=[F.as_int(k, 0) if str(k).isdigit() else k for k in b.keys()])

@F.register(
    'game_delroleactorconf', 'game_delrolebulletconf', 'game_delroleweaponconf',
    'game_delrolepropconf', 'game_delroletileconf', 'game_delroledeviceconf',
    'game_delrolecreativeconf', 'game_delrolegamedata', 'game_delworlddata',
    'game_delvariable', 'game_delcustomcolors', 'game_delactorgroups',
    'game_delgameshop')
def h_delconf(req):
    c = cmd(req, 'game_delroleactorconf')
    u = F.uid()
    ids = F.as_list(F.first(req, [], 'ids', 'id', 'confId', 'groupName'))
    def fn(ft, db):
        b = _bucket(ft, u, c)
        for i in ids: b.pop(str(i), None)
    F.mutate(fn)
    return F.payload(c, ids=[F.as_int(x, 0) for x in ids])

# ============================ 作品发布 ============================
@F.register('game_publishgame', 'game_uploadreleasegame', 'game_uploadgoods')
def h_publish(req):
    c = cmd(req, 'game_publishgame')
    u = F.uid()
    gid = F.first(req, None, 'id', 'gameId')
    name = str(F.first(req, '我的作品', 'name') or '我的作品')[:40]
    def fn(ft, db):
        if c == 'game_uploadgoods':
            nid = F.next_id(ft, 'goods')
            ft.setdefault('goods', []).append({
                'id': nid, 'name': name, 'price': F.as_int(F.first(req, 0, 'price'), 0),
                'playerId': F.as_int(u, 0), 'goodsType': 0, 'iconTextureName': '',
                'saleCnt': 0, 'collectionCnt': 0, 'upStamp': F.now_ms(), 'status': 1,
            })
            return nid
        nid = F.as_int(gid, 0) if gid else F.next_id(ft, 'game')
        games = ft.setdefault('games', [])
        rec = {
            'id': nid, 'name': name, 'iconTextureName': str(F.first(req, 'demo1.png', 'iconTextureName') or 'demo1.png'),
            'rank': len(games) + 13, 'thumbCnt': 0, 'collectionCnt': 0,
            'playCnt': 0, 'hurryCnt': 0, 'advert': str(F.first(req, '', 'advert') or ''),
            'openCreativeGame': False, 'lastPublishTime': F.now_ms(),
            '_uid': str(u), '_stamp': F.now_ms(), 'status': 1,
        }
        # 同 id 覆盖（重复发布 = 更新）
        games[:] = [g for g in games if str(g.get('id')) != str(nid)]
        games.append(rec)
        # 累计作品数
        us = db.get('users', {})
        if isinstance(us, dict) and str(u) in us:
            us[str(u)]['workCount'] = len([g for g in games if str(g.get('_uid')) == str(u)])
        return nid
    nid = F.mutate(fn)
    return F.payload(c, id=nid, code=0, cdnUrl='', sensitiveWords=[])

# ============================ 账号资料 / 生命周期 ============================
@F.register('game_updateuserinfo')
def h_updateuserinfo(req):
    u = F.uid()
    patch = {}
    for src, dst in (('userName', 'userName'), ('userImg', 'userImg'),
                     ('userIntro', 'userIntro'), ('sign', 'sign'), ('userSex', 'userSex')):
        v = F.param(req, src)
        if v is not None:
            patch[dst] = str(v)[:120] if isinstance(v, str) else v
    def fn(ft, db):
        us = db.get('users', {})
        if isinstance(us, dict) and str(u) in us and patch:
            us[str(u)].update(patch)
    if patch: F.mutate(fn)
    return F.payload('game_updateuserinfo', code=0, sensitiveWords=[])

# 注意：game_addcoinbyshare / game_additem 由 feat_shop 真实实现；
# game_clearnewmsg 由 feat_social.h_cleardot 真实清红点。此处不再重复注册，
# 否则（editor 晚于 social 加载）会用占位 handler 覆盖掉真实逻辑。
@F.register('game_inited', 'game_on_show', 'game_on_hide', 'game_on_restart',
            'game_addiction_quit', 'game_addiction_switch_account',
            'game_checkhappymoment', 'game_gmlogin')
def h_lifecycle(req):
    """纯生命周期/前后台通知：客户端不等有效数据，回当前 G币即可。"""
    c = cmd(req, 'game_inited')
    return F.payload(c, coin=F.as_int(F.coin(), 9999))

# -------------------- GM / 活动：绑定角色、得币、考试分数 --------------------
def _add_coin_db(db, delta):
    u = str(F.uid())
    us = db.get('users', {})
    if isinstance(us, dict) and u in us:
        cur = max(0, F.as_int(us[u].get('coin'), 0) + delta)
        for k in ('coin', 'gCoin', 'g币'):
            us[u][k] = cur
        return cur
    return F.as_int(F.coin(), 0)

@F.register('game_gmincothercoin', 'game_obtainttcoin0319')
def h_gmcoin(req):
    """GM 加币 / 活动得币：真实加 G币，回最新余额。"""
    c = cmd(req, 'game_gmincothercoin')
    delta = F.as_int(F.first(req, 100, 'coin', 'count', 'addCoin'), 100)
    def fn(ft, db):
        return _add_coin_db(db, abs(delta))
    cur = F.mutate(fn)
    return F.payload(c, coin=cur, curCoin=cur, errorCode=0)

@F.register('game_bindrole', 'game_gmbindrole', 'game_gmrevokebindrole',
            'game_getbindrolemsg')
def h_bindrole(req):
    """绑定角色：真实读写 bindRole；revoke 解绑，get 返回绑定状态。"""
    c = cmd(req, 'game_bindrole')
    u = str(F.uid())
    is_get = c == 'game_getbindrolemsg'
    is_revoke = 'revoke' in c
    def fn(ft, db):
        br = ft.setdefault('bindRole', {})
        if is_revoke:
            br.pop(u, None)
            return {}
        if is_get:
            return dict(br.get(u, {}))
        rec = br.setdefault(u, {})
        rec.update({
            'id': F.as_int(rec.get('id'), 0) or F.next_id(ft, 'conf'),
            'bindIP': str(F.first(req, '', 'bindIP', 'ip') or ''),
            'bindType': F.as_int(F.first(req, 1, 'bindType', 'type'), 1),
            'bindCode': str(F.first(req, '', 'bindCode', 'code') or ''),
            'bindTime': F.now_ms(),
            'playerId': F.as_int(u, 0),
        })
        return dict(rec)
    rec = F.mutate(fn)
    return F.payload(c, code=0, errorCode=0, user=rec, bindRoleInfo=rec,
                     isBind=bool(rec), bindRole=rec)

@F.register('game_uploadtakeexamscore')
def h_exam(req):
    """上传考试分数：真实记录到 ft['examScore'][uid]，取历史最高。"""
    c = cmd(req, 'game_uploadtakeexamscore')
    score = F.as_int(F.first(req, 0, 'score', 'examScore'), 0)
    u = str(F.uid())
    def fn(ft, db):
        rec = ft.setdefault('examScore', {}).get(u, {'score': 0, 'best': 0, 'cnt': 0})
        rec['score'] = score
        rec['best'] = max(F.as_int(rec.get('best'), 0), score)
        rec['cnt'] = F.as_int(rec.get('cnt'), 0) + 1
        rec['stamp'] = F.now_ms()
        ft.setdefault('examScore', {})[u] = rec
        return dict(rec)
    rec = F.mutate(fn)
    return F.payload(c, score=score, bestScore=rec['best'], code=0)

# 广告/视频/分享得币 与 游戏内消费 已统一由 feat_shop 真实实现（含每日防刷/余额校验），
# 此处只保留 GM 专属的 game_gmsetgold，避免重复注册互相覆盖。
@F.register('game_gmsetgold')
def h_coin(req):
    c = cmd(req, 'game_addcoinbyadvert')
    delta = F.as_int(F.first(req, 10, 'coin', 'count', 'addCoin'), 10)
    if c in ('game_costcoiningame',): delta = -abs(delta)
    def fn(ft, db):
        us = db.get('users', {}); u = str(F.uid())
        if isinstance(us, dict) and u in us:
            cur = F.as_int(us[u].get('coin'), 0) + delta
            cur = max(0, cur)
            for k in ('coin', 'gCoin', 'g币'): us[u][k] = cur
            return cur
        return 0
    cur = F.mutate(fn)
    return F.payload(c, coin=cur, curCoin=cur, addCoinByAdvertCnt=1,
                     addCoinByAdvertLimit=10, addCoinByAdvertReset=0)
