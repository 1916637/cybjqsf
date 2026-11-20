#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""私服后台管理界面  https://<你的服务器IP>:38443

安全：高强度随机密码(bcrypt) + 签名会话 + CSRF + 登录失败限流 + 安全响应头 + 审计日志。
功能：管理所有用户(任意字段，含 G币/蓝V) 与 动态(编辑/删除/清空)；新增/删除用户。
数据：全部经 store.py 共享层（flock + 原子写），与 server(HTTP)/agentsrv(WS) 实时一致。
"""
import os, sys, json, time, secrets, hmac, html, re, functools, base64
sys.path.insert(0, '/opt/privsrv')
import store
import review
import features as F
from flask import Flask, request, session, redirect, abort, Response
import bcrypt

BASE = '/opt/privsrv'
AUTH_FILE = os.path.join(BASE, 'data', 'admin_auth.json')
AUDIT = os.path.join(BASE, 'logs', 'admin.log')
CERT = os.path.join(BASE, 'certs', 'admin.crt')
KEY = os.path.join(BASE, 'certs', 'admin.key')
PORT = 38443


def h(s):
    return html.escape(str(s), quote=True)


def _load_auth():
    d = json.load(open(AUTH_FILE, encoding='utf8'))
    if not d.get('pw_hash') or not d.get('secret'):
        raise RuntimeError('admin_auth.json 不完整')
    return d


_auth = _load_auth()
app = Flask(__name__)
app.secret_key = _auth['secret']
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=1024 * 1024,
)

# ---------------- 限流 / 审计 / CSRF ----------------
_fails = {}   # ip -> [fail_count, lock_until]


def audit(action, detail=''):
    try:
        with open(AUDIT, 'a', encoding='utf8') as f:
            f.write('%s  %s  %s  %s\n' % (
                time.strftime('%F %T'), request.remote_addr, action,
                str(detail).replace('\n', ' ')[:220]))
    except Exception:
        pass


def rate_locked(ip):
    c, until = _fails.get(ip, [0, 0])
    return time.time() < until


def rate_fail(ip):
    c, until = _fails.get(ip, [0, 0])
    c += 1
    if c >= 5:
        until, c = time.time() + 900, 0
    _fails[ip] = [c, until]


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(16)
    return session['csrf']


def csrf_ok():
    return hmac.compare_digest(str(request.form.get('_csrf', '')),
                               str(session.get('csrf', '')))


@app.before_request
def guard():
    ep = request.endpoint or ''
    if ep in ('login', 'static'):
        return
    if not session.get('ok'):
        return redirect('/login')
    if request.method == 'POST' and not csrf_ok():
        audit('CSRF_REJECT', request.path)
        abort(403)


@app.after_request
def sec_headers(r):
    r.headers['X-Frame-Options'] = 'DENY'
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['Referrer-Policy'] = 'no-referrer'
    r.headers['Content-Security-Policy'] = (
        "default-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
    r.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    r.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    r.headers['X-XSS-Protection'] = '1; mode=block'
    return r


@app.errorhandler(403)
def e403(e):
    return Response('403 禁止访问（CSRF 校验失败或越权）', status=403, mimetype='text/plain; charset=utf-8')


@app.errorhandler(404)
def e404(e):
    return Response('404 页面不存在', status=404, mimetype='text/plain; charset=utf-8')


@app.errorhandler(500)
def e500(e):
    audit('ERROR', repr(e))
    return Response('500 请求处理失败，请返回重试（详情见审计日志）', status=500,
                    mimetype='text/plain; charset=utf-8')


# ---------------- 页面骨架 ----------------
CSS = """
*{box-sizing:border-box}body{margin:0;background:#0f1420;color:#e6e9f0;
font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif}
a{color:#6db3ff;text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto;padding:0 18px 60px}
header{display:flex;align-items:center;gap:22px;padding:18px 0;border-bottom:1px solid #232b3d;margin-bottom:22px;flex-wrap:wrap}
.brand{font-size:19px;font-weight:700;color:#fff}
nav a{margin-right:16px;color:#9fb0cc}nav a.on{color:#6db3ff;font-weight:600}
.sp{flex:1}
h1{font-size:20px;margin:0 0 16px}h2{font-size:16px;margin:26px 0 12px;color:#9fb0cc}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}
.card{background:#171e2e;border:1px solid #262f45;border-radius:10px;padding:16px 20px;min-width:150px}
.card b{display:block;font-size:26px;color:#6db3ff;margin-top:4px}
.card span{color:#8a97b0;font-size:12px}
table{width:100%;border-collapse:collapse;background:#141b29;border-radius:10px;overflow:hidden}
th,td{padding:9px 11px;border-bottom:1px solid #222a3c;text-align:left;font-size:13px;vertical-align:top}
th{background:#1b2335;color:#9fb0cc;font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:none}
input,select,textarea{background:#0e1521;color:#e6e9f0;border:1px solid #2d3852;border-radius:6px;
padding:7px 9px;font:inherit;max-width:100%}
input[type=text]{width:100%}
.btn{display:inline-block;background:#2f6fed;color:#fff;border:0;border-radius:6px;
padding:8px 15px;cursor:pointer;font:inherit;margin:2px 4px 2px 0}
.btn.gray{background:#3a4560}.btn.red{background:#c0392b}.btn.sm{padding:4px 10px;font-size:12px}
.btn:hover{filter:brightness(1.12)}
.box{background:#141b29;border:1px solid #262f45;border-radius:10px;padding:18px;margin-bottom:18px}
.frow{display:flex;gap:10px;align-items:center;margin:7px 0}
.frow label{width:250px;color:#9fb0cc;flex-shrink:0;word-break:break-all;line-height:1.35}
.frow label b{color:#dbe4f5;font-weight:600}
.frow input{flex:1}
.fkey{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:#7d8aa4}
.ftip{font-size:11px;color:#8292b0;font-weight:400}
.grp{font-size:13px;color:#6db3ff;margin:22px 0 10px;padding-bottom:6px;border-bottom:1px solid #232b3d}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#9fe0b0}
.muted{color:#7d8aa4;font-size:12px}
.badge{background:#8a5a00;color:#ffd88a;border-radius:4px;padding:1px 7px;font-size:11px}
.talk{background:#171e2e;border:1px solid #262f45;border-radius:9px;padding:13px 16px;margin-bottom:11px}
.talk .t{font-weight:600;color:#fff}.talk .m{color:#8a97b0;font-size:12px;margin:3px 0 9px}
.loginwrap{max-width:400px;margin:9vh auto}
.msg{background:#3a2020;border:1px solid #7a3030;color:#ffb4b4;padding:10px 14px;border-radius:8px;margin-bottom:14px}
.tip{background:#16263a;border:1px solid #2a4a6a;color:#a9cdf5;padding:10px 14px;border-radius:8px;margin-bottom:16px;font-size:13px}
"""


def page(title, body, nav=''):
    return ('<!doctype html><html lang="zh"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>' + h(title) + ' - 私服后台</title><style>' + CSS + '</style></head><body>'
            '<div class="wrap"><header><div class="brand">创游私服 · 管理后台</div>'
            '<nav><a href="/" class="' + ('on' if nav == 'home' else '') + '">概览</a>'
            '<a href="/users" class="' + ('on' if nav == 'users' else '') + '">用户</a>'
            '<a href="/talks" class="' + ('on' if nav == 'talks' else '') + '">动态</a>'
            '<a href="/reviews" class="' + ('on' if nav == 'reviews' else '') + '">头像审核</a>'
            '<a href="/goods" class="' + ('on' if nav == 'goods' else '') + '">商品</a>'
            '<a href="/comments" class="' + ('on' if nav == 'comments' else '') + '">评论</a>'
            '<a href="/reports" class="' + ('on' if nav == 'reports' else '') + '">举报</a>'
            '<a href="/feat" class="' + ('on' if nav == 'feat' else '') + '">互动数据</a></nav>'
            '<div class="sp"></div><a href="/logout">退出登录</a></header>'
            '<main>' + body + '</main></div></body></html>')


def csrf_hidden():
    return '<input type="hidden" name="_csrf" value="' + h(csrf_token()) + '">'


# ---------------- 登录 ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr or '?'
    msg = ''
    if request.method == 'POST':
        if rate_locked(ip):
            msg = '失败次数过多，已锁定 15 分钟'
            audit('LOGIN_LOCKED', ip)
        elif not csrf_ok():
            msg = '表单校验失败，请刷新重试'
        else:
            pw = request.form.get('password', '')
            okpw = False
            try:
                okpw = bcrypt.checkpw(pw.encode('utf8'), _auth['pw_hash'].encode('utf8'))
            except Exception:
                okpw = False
            if okpw:
                _fails.pop(ip, None)
                session.clear()
                session['ok'] = True
                session.permanent = True
                session['csrf'] = secrets.token_hex(16)
                audit('LOGIN_OK')
                return redirect('/')
            rate_fail(ip)
            audit('LOGIN_FAIL', ip)
            msg = '密码错误'
    tok = csrf_token()
    body = ('<div class="loginwrap"><h1>私服管理后台</h1>'
            '<div class="tip">高强度随机密码保护 · 全程 HTTPS · 登录失败 5 次锁定 15 分钟</div>'
            + ('<div class="msg">' + h(msg) + '</div>' if msg else '') +
            '<form method="post" action="/login" class="box">'
            '<input type="hidden" name="_csrf" value="' + h(tok) + '">'
            '<div class="frow"><label>管理密码</label>'
            '<input type="password" name="password" autofocus required style="flex:1"></div>'
            '<div style="margin-top:14px"><button class="btn" type="submit">登 录</button></div>'
            '</form></div>')
    return Response(page('登录', body), mimetype='text/html; charset=utf-8')


@app.route('/logout')
def logout():
    audit('LOGOUT')
    session.clear()
    return redirect('/login')


# ---------------- 概览 ----------------
@app.route('/')
def index():
    db = store.load_db()
    talks = store.load_talks()
    gm = store.gm_ids()
    cur = store.current_user()
    ft = db.get('feat') if isinstance(db.get('feat'), dict) else {}
    def _n(k):
        v = ft.get(k)
        return len(v) if isinstance(v, (list, dict)) else 0
    _reports = ft.get('reports', []) if isinstance(ft.get('reports'), list) else []
    pending = sum(1 for r in _reports if isinstance(r, dict) and not r.get('status'))
    cards = ('<div class="cards">'
             '<div class="card"><span>用户总数</span><b>' + str(len(db['users'])) + '</b></div>'
             '<div class="card"><span>动态总数</span><b>' + str(len(talks)) + '</b></div>'
             '<div class="card"><span>蓝V认证数</span><b>' + str(len(gm) // 2) + '</b></div>'
             '<div class="card"><span>会话/令牌</span><b>' + str(len(db['tokens'])) + '</b></div>'
             '<div class="card"><span>待审头像</span><b>' +
             str(sum(1 for r in db.get('reviews', []) if r.get('status') == review.INREVIEW)) +
             '</b></div>'
             '<div class="card"><span>商城商品</span><b>' +
             str(len(_seed_goods()) + _n('goods')) + '</b></div>'
             '<div class="card"><span>社区评论</span><b>' + str(_n('comments')) + '</b></div>'
             '<div class="card"><span>待处理举报</span><b>' + str(pending) + '</b></div>'
             '<div class="card"><span>消息通知</span><b>' + str(_n('msgs')) + '</b></div></div>')
    curtxt = (h(cur.get('userName')) + ' (ID ' + h(cur.get('userId')) + ', G币 ' +
              h(cur.get('coin')) + ')') if isinstance(cur, dict) else '（无，等待客户端登录）'
    body = ('<h1>概览</h1>' + cards +
            '<div class="box"><h2 style="margin-top:0">当前游戏会话账号</h2>' + curtxt +
            '<div class="muted" style="margin-top:6px">客户端用手机号登录后，'
            'game_login 与「我的」页会自动读取此账号的全部字段。</div></div>' +
            '<div class="box"><h2 style="margin-top:0">蓝V（官方认证）名单</h2>' +
            (('<span class="mono">' + h(json.dumps(gm, ensure_ascii=False)) + '</span>')
             if gm else '<span class="muted">无。在「用户」里把某账号的 <b>蓝V官方认证（authed）</b> 填 <b>true</b> 即授予蓝V（服务端生效）。</span>') +
            '</div>' +
            '<div class="tip">提示：本后台与游戏服务端共用同一份数据（store.py，带文件锁 + 原子写）。'
            '在这里改动 G币 / 等级 / 蓝V / 动态后，客户端重新登录 game_login 即读到新值，无需重启服务。</div>')
    return Response(page('概览', body, 'home'), mimetype='text/html; charset=utf-8')


# ---------------- 用户 ----------------
# 字段中英对照：编辑页 label 主显中文，英文原名以小字附在下方（name=f_xxx 不变，保证保存逻辑不受影响）
FIELD_CN = {
    'userId': '用户ID', 'uniqueId': '唯一标识', 'userName': '昵称',
    'phone': '登录手机号', 'coin': 'G币（金币）', 'gCoin': 'G币（同步字段）',
    'g币': 'G币（同步·中文键）', 'diamond': '钻石', 'level': '等级',
    'exp': '经验值', 'userImg': '头像地址', 'userIntro': '个人简介',
    'userSex': '性别', 'city': '城市', 'province': '省份',
    'birthday': '生日', 'brithDay': '生日（客户端字段）',
    'isRealName': '是否已实名', 'authed': '蓝V官方认证',
    'realName': '已实名标记', 'realNamed': '已实名标记',
    'isAdult': '是否成年', 'age': '年龄',
    'shareCode': '邀请码 / 分享码', 'sign': '个性签名',
    'gameId': '游戏ID', 'loginPlatform': '登录平台',
    'deviceID': '设备ID', 'timestamp': '注册时间戳',
    'userPlatforms': '绑定平台', 'hortorChannel': '渠道标识',
    'qqUnionId': 'QQ互联ID', 'dict': '扩展数据',
    'followCount': '关注数', 'fansCount': '粉丝数', 'workCount': '作品数',
}

# 关键字段的填写提示（直接显示在字段下方，不用再查表）
FIELD_TIP = {
    'coin': '填一个即可，coin / gCoin / g币 自动同步',
    'gCoin': '与 coin 自动同步，改哪个都行',
    'g币': '与 coin 自动同步，改哪个都行',
    'authed': 'true = 授予蓝V；false = 取消',
    'level': '数字，如 10（发动态需 ≥5）',
    'diamond': '数字，如 100',
    'exp': '数字，经验值',
    'userName': '游戏内显示的昵称',
    'userIntro': '个人简介，可留空',
    'sign': '个性签名，可留空',
    'userImg': '头像图片地址，可留空',
    'phone': '登录用手机号（任意验证码）',
    'userSex': '0=未知  1=男  2=女',
    'isRealName': '保持 true，改 false 会弹实名框',
    'realName': '保持 true，改 false 会弹实名框',
    'realNamed': '保持 true，改 false 会弹实名框',
    'isAdult': '保持 true（成年）',
    'userPlatforms': '保持 ["app-mobile"]，清空会变游客',
    'brithDay': '客户端原字段名就是这个拼写，勿改名',
    'birthday': '格式 1990-01-01',
    'userId': '账号唯一ID，不建议修改',
    'uniqueId': '账号唯一标识，不建议修改',
    'dict': 'JSON 对象，如 {}',
    'timestamp': 'Unix 秒级时间戳',
}

# 分组：常用字段置顶，避免一屏英文无从下手
FIELD_GROUPS = [
    ('① 常用设置（改这些就够了）',
     ['userName', 'phone', 'coin', 'gCoin', 'g币', 'diamond', 'level', 'exp',
      'authed', 'userIntro', 'sign', 'userImg', 'userSex', 'age',
      'city', 'province', 'birthday', 'brithDay', 'shareCode']),
    ('② 账号与状态（谨慎修改）',
     ['userId', 'uniqueId', 'isRealName', 'realName', 'realNamed', 'isAdult',
      'userPlatforms', 'loginPlatform', 'gameId', 'hortorChannel',
      'deviceID', 'qqUnionId', 'dict']),
    ('③ 统计数据（一般不用改）',
     ['fansCount', 'followCount', 'workCount', 'timestamp']),
    ('④ 其他 / 自定义字段', None),
]

KEY_RE = re.compile(r'^[A-Za-z0-9_\u4e00-\u9fa5]{1,40}$')


def valid_key(k):
    return bool(KEY_RE.match(k)) and not k.startswith('__')


def coerce(s):
    s = s.strip()
    if s == '':
        return ''
    low = s.lower()
    if low == 'true':
        return True
    if low == 'false':
        return False
    if low in ('null', 'none'):
        return None
    if re.fullmatch(r'-?\d+', s):
        try:
            return int(s)
        except Exception:
            pass
    if re.fullmatch(r'-?\d+\.\d+', s):
        try:
            return float(s)
        except Exception:
            pass
    if s[:1] in ('{', '['):
        try:
            return json.loads(s)
        except Exception:
            pass
    return s[:2000]


@app.route('/users')
def users():
    db = store.load_db()
    rows = []
    for uid, u in sorted(db['users'].items(), key=lambda x: str(x[0])):
        blue = ' <span class="badge">蓝V</span>' if u.get('authed') else ''
        rows.append('<tr><td class="mono">' + h(uid) + '</td>'
                    '<td>' + h(u.get('userName', '')) + blue + '</td>'
                    '<td>' + h(u.get('phone', '')) + '</td>'
                    '<td class="mono">' + h(u.get('coin', '')) + '</td>'
                    '<td>' + h(u.get('level', '')) + '</td>'
                    '<td>' + h(u.get('diamond', '')) + '</td>'
                    '<td><a class="btn sm" href="/user/' + h(uid) + '">编辑字段</a>'
                    '<form method="post" action="/user/' + h(uid) + '/delete" style="display:inline" '
                    'onsubmit="return confirm(\'确认删除该用户？\')">' + csrf_hidden() +
                    '<button class="btn sm red" type="submit">删除</button></form></td></tr>')
    table = ('<table><tr><th>ID</th><th>昵称</th><th>手机号</th><th>G币(coin)</th>'
             '<th>等级</th><th>钻石</th><th>操作</th></tr>' +
             (''.join(rows) if rows else '<tr><td colspan="7" class="muted">暂无用户（客户端用手机号登录会自动创建）</td></tr>') +
             '</table>')
    add = ('<div class="box"><h2 style="margin-top:0">新增用户</h2>'
           '<form method="post" action="/user/add">' + csrf_hidden() +
           '<div class="frow"><label>手机号（留空自动生成）</label><input type="text" name="phone"></div>'
           '<div class="frow"><label>昵称</label><input type="text" name="name"></div>'
           '<button class="btn" type="submit" style="margin-top:10px">创建用户</button></form></div>')
    return Response(page('用户管理', '<h1>用户管理 <span class="muted">共 ' +
                         str(len(db['users'])) + ' 个</span></h1>' + table + add, 'users'),
                    mimetype='text/html; charset=utf-8')


@app.route('/user/<uid>')
def user_edit(uid):
    db = store.load_db()
    u = db['users'].get(uid)
    if not isinstance(u, dict):
        return Response('用户不存在', status=404, mimetype='text/plain; charset=utf-8')
    def row(k, v):
        vs = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
        cn = FIELD_CN.get(k, '')
        if cn:
            lab = '<label><b>' + h(cn) + '</b><br><span class="fkey">' + h(k) + '</span>'
        else:
            lab = '<label><b>' + h(k) + '</b>'
        tip = FIELD_TIP.get(k, '')
        if tip:
            lab += '<br><span class="ftip">' + h(tip) + '</span>'
        lab += '</label>'
        # name="f_<原字段名>" 保持不变，保存逻辑完全不动
        return ('<div class="frow">' + lab + '<input type="text" name="f_' + h(k) +
                '" value="' + h(vs) + '"></div>')

    keys = sorted(u.keys())
    used = set()
    parts = []
    for title, ks in FIELD_GROUPS:
        group = [k for k in keys if k not in used] if ks is None else [k for k in ks if k in u]
        used.update(group)
        if not group:
            continue
        parts.append('<h2 class="grp">' + h(title) + '</h2>')
        for k in group:
            parts.append(row(k, u[k]))

    body = ('<h1>编辑用户 <span class="mono">' + h(uid) + '</span></h1>'
            '<div class="tip"><b>怎么填（每个字段下方都标了中文名和填写说明）</b><br>'
            '· 想加钱：改 <b>G币（coin）</b> 或 <b>钻石（diamond）</b>，填数字；G币三个字段自动同步<br>'
            '· 想给蓝V：把 <b>蓝V官方认证（authed）</b> 填 <span class="mono">true</span>，取消填 <span class="mono">false</span><br>'
            '· 想改昵称/等级：改 <b>昵称（userName）</b> / <b>等级（level）</b>（发动态需 ≥5）<br>'
            '· 布尔值统一填小写 <span class="mono">true</span> / <span class="mono">false</span>；'
            '列表或对象填 JSON，如 <span class="mono">["app-mobile"]</span>、<span class="mono">{}</span>；留空 = 空字符串<br>'
            '· 改完点「保存全部」，客户端重新登录即生效，无需重启服务</div>'
            '<form method="post" action="/user/' + h(uid) + '/save" class="box">' + csrf_hidden() +
            ''.join(parts) +
            '<h2 class="grp">⑤ 新增自定义字段（可选）</h2>'
            '<div class="frow"><label><b>字段名</b><br><span class="fkey">new_key</span></label>'
            '<input type="text" name="new_key" placeholder="英文或中文，如 vipLevel"></div>'
            '<div class="frow"><label><b>值</b><br><span class="fkey">new_val</span></label>'
            '<input type="text" name="new_val" placeholder="数字 / true / false / JSON"></div>'
            '<div style="margin-top:16px"><button class="btn" type="submit">保存全部</button>'
            '<a class="btn gray" href="/users">返回</a></div></form>'
            + credit_admin_box(uid))
    return Response(page('编辑用户', body, 'users'), mimetype='text/html; charset=utf-8')


def credit_admin_box(uid):
    """用户详情页内的信誉分管理表单：后台手动加/扣信誉分并填理由。"""
    return ('<h2 class="grp">信誉分管理</h2>'
            '<div class="tip">对当前用户手动 <b>加 / 扣</b> 信誉分（等级点），并填写理由。理由会显示在 APP 的「信誉分」'
            '界面（CreditScene）。分值区间 <b>0–3</b>：满 3 全绿叶子，每扣 1 点掉 1 片叶子，扣到 0 即封号。'
            '改完客户端重新登录即生效，无需重启。</div>'
            '<form method="post" action="/user/' + h(uid) + '/credit" class="box">' + csrf_hidden() +
            '<div class="frow"><label><b>操作</b><br><span class="fkey">op</span></label>'
            '<select name="op"><option value="inc">加分</option><option value="dec">扣分</option></select></div>'
            '<div class="frow"><label><b>分值</b><br><span class="fkey">score</span></label>'
            '<input type="text" name="score" value="1"></div>'
            '<div class="frow"><label><b>理由</b><br><span class="fkey">reason</span></label>'
            '<input type="text" name="reason" placeholder="如：发布违规内容 / 优质创作奖励" value=""></div>'
            '<div style="margin-top:12px"><button class="btn" type="submit">提交</button></div></form>')


def adjust_credit(db, uid, delta, reason):
    """后台手动调整信誉分（0~3 等级点）：改 ft.credit[uid].score 并留一条 UserCreditMsg 明细，同步 db.users[uid].creditScore。"""
    uid = str(uid)
    feat = db.setdefault('feat', {})
    rec = feat.setdefault('credit', {}).setdefault(uid, {'score': 3, 'list': []})
    old = F.as_int(rec.get('score'), 3)
    new = max(0, min(3, old + delta))   # 信誉分等级点区间 0–3（3=满，0=封号）
    rec['score'] = new
    rec.setdefault('list', []).append({
        'score': delta, 'reason': reason, 'stamp': int(time.time() * 1000),
    })
    rec['list'] = rec['list'][-50:]
    u = db['users'].get(uid)
    if isinstance(u, dict):
        u['creditScore'] = new
    store.save_db(db)
    return new


@app.route('/user/<uid>/credit', methods=['POST'])
def user_credit(uid):
    db = store.load_db()
    u = db['users'].get(uid)
    if not isinstance(u, dict):
        return Response('用户不存在', status=404, mimetype='text/plain; charset=utf-8')
    op = request.form.get('op', 'inc')
    try:
        score = max(0, min(3, int(float(request.form.get('score', '0') or 0))))
    except Exception:
        score = 0
    if op == 'inc':
        delta, label = score, '加分'
    else:
        delta, label = -score, '扣分'
    reason = (request.form.get('reason', '') or '').strip()[:200] or ('后台' + label)
    new = adjust_credit(db, uid, delta, reason)
    audit('USER_CREDIT', uid + ' op=' + op + ' score=' + str(score) +
          ' delta=' + str(delta) + ' -> ' + str(new))
    return redirect('/user/' + uid)


@app.route('/user/<uid>/save', methods=['POST'])
def user_save(uid):
    db = store.load_db()
    u = db['users'].get(uid)
    if not isinstance(u, dict):
        return Response('用户不存在', status=404, mimetype='text/plain; charset=utf-8')
    changed = []
    for key, val in request.form.items():
        if key.startswith('f_'):
            k = key[2:]
            if valid_key(k):
                nv = coerce(val)
                if u.get(k) != nv:
                    changed.append(k)
                u[k] = nv
    nk = request.form.get('new_key', '').strip()
    if nk and valid_key(nk):
        u[nk] = coerce(request.form.get('new_val', ''))
        changed.append('+' + nk)
    # coin / gCoin / g币 三者同步（取被改的那个）
    coin_val = None
    for k in ('coin', 'gCoin', 'g币'):
        if k in changed:
            coin_val = u.get(k)
            break
    if coin_val is not None:
        for k in ('coin', 'gCoin', 'g币'):
            u[k] = coin_val
    store.save_db(db)
    audit('USER_SAVE', uid + ' ' + ','.join(changed[:20]))
    return redirect('/user/' + uid)


@app.route('/user/add', methods=['POST'])
def user_add():
    phone = request.form.get('phone', '').strip() or ('admin_%d' % int(time.time()))
    name = request.form.get('name', '').strip() or None
    before = store.load_db().get('currentUid', '')
    u, is_new = store.register_or_login(phone, name)
    if before:
        store.set_current(before)   # 不因后台新增用户改变客户端当前会话
    audit('USER_ADD', str(u.get('userId')) + ' new=' + str(is_new))
    return redirect('/users')


@app.route('/user/<uid>/delete', methods=['POST'])
def user_delete(uid):
    db = store.load_db()
    db['users'].pop(uid, None)
    db['tokens'] = {t: v for t, v in db['tokens'].items() if str(v) != str(uid)}
    db['phoneMap'] = {p: v for p, v in db['phoneMap'].items() if str(v) != str(uid)}
    if str(db.get('lastUser')) == str(uid):
        db['lastUser'] = ''
    if str(db.get('currentUid')) == str(uid):
        db['currentUid'] = ''
    store.save_db(db)
    audit('USER_DELETE', uid)
    return redirect('/users')


# ---------------- 动态 ----------------
@app.route('/talks')
def talks():
    ts = store.load_talks()[::-1]
    blocks = []
    for t in ts:
        tid = str(t.get('talkId', ''))
        title = str(t.get('title', ''))
        sc = t.get('simpleContent')
        text = sc.get('text', '') if isinstance(sc, dict) else str(sc or '')
        author = str(t.get('userName', ''))
        stamp = t.get('createStamp', 0)
        try:
            ts_str = time.strftime('%F %T', time.localtime(int(stamp) / 1000))
        except Exception:
            ts_str = str(stamp)
        blocks.append(
            '<div class="talk"><div class="t">' + h(title) + '</div>'
            '<div class="m">作者 ' + h(author) + ' · ' + h(ts_str) +
            ' · 点赞 ' + h(t.get('upCnt', 0)) + ' · ID <span class="mono">' + h(tid) + '</span></div>'
            '<form method="post" action="/talk/' + h(tid) + '/save">' + csrf_hidden() +
            '<div class="frow"><label>标题</label><input type="text" name="title" value="' + h(title) + '"></div>'
            '<div class="frow"><label>正文</label><input type="text" name="text" value="' + h(text) + '"></div>'
            '<button class="btn sm" type="submit">保存</button></form>'
            '<form method="post" action="/talk/' + h(tid) + '/delete" style="display:inline" '
            'onsubmit="return confirm(\'确认删除该动态？\')">' + csrf_hidden() +
            '<button class="btn sm red" type="submit">删除动态</button></form></div>')
    clear = ('<form method="post" action="/talks/clear" '
             'onsubmit="return confirm(\'确认清空全部动态？不可恢复\')">' + csrf_hidden() +
             '<button class="btn red" type="submit">清空全部动态</button></form>')
    body = ('<h1>动态管理 <span class="muted">共 ' + str(len(ts)) + ' 条</span></h1>'
            '<div class="tip">客户端「发动态」会写入这里，删除即时生效（game_loadtalk 读到更新后的列表）。</div>'
            + clear + '<div style="height:14px"></div>'
            + (''.join(blocks) if blocks else '<div class="box muted">暂无动态</div>'))
    return Response(page('动态管理', body, 'talks'), mimetype='text/html; charset=utf-8')


@app.route('/talk/<tid>/save', methods=['POST'])
def talk_save(tid):
    title = request.form.get('title', '')[:120]
    text = request.form.get('text', '')[:1000]
    store.patch_talk(tid, {'title': title, 'simpleContent': {'text': text}})
    audit('TALK_SAVE', tid)
    return redirect('/talks')


@app.route('/talk/<tid>/delete', methods=['POST'])
def talk_delete(tid):
    n = store.del_talk(tid)
    audit('TALK_DELETE', tid + ' removed=' + str(n))
    return redirect('/talks')


@app.route('/talks/clear', methods=['POST'])
def talks_clear():
    store.save_talks([])
    audit('TALK_CLEAR')
    return redirect('/talks')


# ---------------- 头像审核 ----------------
def _review_thumb(url):
    """把 /uploads/cover/xxx.png 读成 data URI 缩略图（CSP img-src 允许 data:）。"""
    rel = str(url or '').lstrip('/')
    if rel.startswith('uploads/'):
        p = os.path.join(BASE, 'uploads', rel[len('uploads/'):])
    else:
        p = os.path.join(BASE, 'uploads', 'cover', rel)
    try:
        raw = open(p, 'rb').read()
        if not raw or len(raw) > 2 * 1024 * 1024:
            return ''
        return 'data:image/png;base64,' + base64.b64encode(raw).decode('ascii')
    except Exception:
        return ''


@app.route('/reviews')
def reviews():
    db = store.load_db()
    rs = sorted(db.get('reviews', []), key=lambda r: r.get('createStamp', 0), reverse=True)
    n_pending = sum(1 for r in rs if r.get('status') == review.INREVIEW)
    cards = ('<div class="cards">'
             '<div class="card"><span>待审核</span><b>' + str(n_pending) + '</b></div>'
             '<div class="card"><span>总记录</span><b>' + str(len(rs)) + '</b></div>'
             '<div class="card"><span>自动通过</span><b>' +
             ('开' if review.auto_enabled() else '关') + '</b></div></div>')
    tip = ('<div class="tip">用户换头像 → 服务端把图片存到 '
           '<span class="mono">/opt/privsrv/uploads/cover/</span> 并生成一条待审核记录。'
           '点「通过」后该账号 <b>userImg</b> 更新为新头像、状态置为「已通过」，'
           'APP <b>重新登录</b>即正常显示，不再提示「新头像审核中」。'
           '「拒绝」则保留旧头像并显示审核失败。</div>')
    auto = ('<div class="box"><h2 style="margin-top:0">自动通过</h2>'
            '<div class="muted" style="margin-bottom:10px">开启后新头像上传即自动通过，无需手动审核。'
            '客户端当前会话仍会短暂显示「审核中」，重新登录生效。</div>'
            '<form method="post" action="/reviews/auto">' + csrf_hidden() +
            '<button class="btn" type="submit" name="auto" value="1">开启自动通过</button>'
            '<button class="btn gray" type="submit" name="auto" value="0">关闭自动通过</button>'
            '</form></div>')
    clear = ('<form method="post" action="/reviews/clear_done" style="margin-bottom:18px">'
             + csrf_hidden() +
             '<button class="btn gray sm" type="submit">清空已处理记录</button></form>')
    blocks = []
    for r in rs:
        st = r.get('status', 0)
        img = _review_thumb(r.get('url'))
        thumb = (('<img src="' + img + '" style="width:76px;height:76px;object-fit:cover;'
                  'border-radius:8px;border:1px solid #2d3852;flex-shrink:0">')
                 if img else '<div class="muted" style="width:76px;flex-shrink:0">无预览</div>')
        badge = {
            '1': '<span class="badge" style="background:#1b5e3a;color:#9ff0c4">已通过</span>',
            '2': '<span class="badge">待审核</span>',
            '3': '<span class="badge" style="background:#6a2020;color:#ffb4b4">已拒绝</span>',
        }.get(str(st), '<span class="muted">已作废</span>')
        ts = time.strftime('%m-%d %H:%M', time.localtime((r.get('createStamp') or 0) / 1000))
        ops = ''
        if st == review.INREVIEW:
            ops = ('<form method="post" action="/review/' + h(r['rid']) + '/approve" style="display:inline">'
                   + csrf_hidden() + '<button class="btn sm" type="submit">通过</button></form>'
                   '<form method="post" action="/review/' + h(r['rid']) + '/reject" style="display:inline">'
                   + csrf_hidden() + '<button class="btn sm red" type="submit">拒绝</button></form>')
        ops += ('<form method="post" action="/review/' + h(r['rid']) + '/delete" style="display:inline">'
                + csrf_hidden() + '<button class="btn sm gray" type="submit">删除</button></form>')
        blocks.append(
            '<div class="talk" style="display:flex;gap:14px;align-items:center">' + thumb +
            '<div style="flex:1;min-width:0"><div class="t">' +
            h(r.get('userName') or ('用户 ' + str(r.get('uid')))) + ' ' + badge + '</div>' +
            '<div class="m">ID ' + h(r.get('uid')) + ' · ' + h(ts) + ' · ' +
            h(r.get('url')) + '</div>' +
            '<div class="muted">' + h(r.get('reason') or '') + '</div>' +
            '<div style="margin-top:8px">' + ops + '</div></div></div>')
    body = ('<h1>头像审核 <span class="muted">共 ' + str(len(rs)) + ' 条</span></h1>' +
            cards + tip + auto + clear +
            (''.join(blocks) if blocks else
             '<div class="box muted">暂无审核记录。用户在 APP 里换一次头像，记录就会出现在这里。</div>'))
    return Response(page('头像审核', body, 'reviews'), mimetype='text/html; charset=utf-8')


@app.route('/review/<rid>/approve', methods=['POST'])
def review_approve(rid):
    db = store.load_db()
    r = review.approve(db, rid)
    store.save_db(db)
    audit('REVIEW_APPROVE', rid + ' uid=' + str((r or {}).get('uid')))
    return redirect('/reviews')


@app.route('/review/<rid>/reject', methods=['POST'])
def review_reject(rid):
    db = store.load_db()
    r = review.reject(db, rid, '后台审核未通过')
    store.save_db(db)
    audit('REVIEW_REJECT', rid + ' uid=' + str((r or {}).get('uid')))
    return redirect('/reviews')


@app.route('/review/<rid>/delete', methods=['POST'])
def review_delete(rid):
    db = store.load_db()
    n = review.delete(db, rid)
    store.save_db(db)
    audit('REVIEW_DELETE', rid + ' removed=' + str(n))
    return redirect('/reviews')


@app.route('/reviews/clear_done', methods=['POST'])
def review_clear_done():
    db = store.load_db()
    n = review.clear_done(db)
    store.save_db(db)
    audit('REVIEW_CLEAR_DONE', 'removed=' + str(n))
    return redirect('/reviews')


@app.route('/reviews/auto', methods=['POST'])
def review_auto():
    v = request.form.get('auto') == '1'
    review.set_auto(v)
    audit('REVIEW_AUTO', 'on' if v else 'off')
    return redirect('/reviews')


# ---------------- 功能层数据管理：商品 / 评论 / 举报 / 互动数据 ----------------
# 数据来自 db.json 顶层 feat 键（与 agentsrv 的 features.py 共用同一份文件 + 同一把 flock 锁）。
def _feat(db=None):
    db = db if isinstance(db, dict) else store.load_db()
    ft = db.get('feat')
    if not isinstance(ft, dict):
        ft = {}
        db['feat'] = ft
    return db, ft


def _seed_goods():
    """内置商品由 feat_shop.py 提供（代码里，清库后仍在）。"""
    try:
        import feat_shop
        return list(feat_shop.SEED_GOODS)
    except Exception:
        return []


def _lst(ft, k):
    v = ft.get(k)
    return v if isinstance(v, list) else []


def _dct(ft, k):
    v = ft.get(k)
    return v if isinstance(v, dict) else {}


def _stamp(v):
    try:
        return time.strftime('%m-%d %H:%M', time.localtime(int(v) / 1000))
    except Exception:
        return '-'


def _save(db, action, detail=''):
    store.save_db(db)
    audit(action, detail)


def _card(label, num):
    return '<div class="card"><span>' + h(label) + '</span><b>' + h(num) + '</b></div>'


# ---- 商品 ----
@app.route('/goods')
def goods():
    db, ft = _feat(store.load_db())
    custom = _lst(ft, 'goods')
    seed = _seed_goods()
    blocks = []
    for g in seed:
        blocks.append('<div class="talk"><div class="t">' + h(g.get('name')) +
                      ' <span class="badge">内置</span></div><div class="m">ID ' + h(g.get('id')) +
                      ' · 价格 ' + h(g.get('price')) + ' G币 · 类型 ' + h(g.get('goodsType')) +
                      ' · 销量 ' + h(g.get('saleCnt')) + '</div></div>')
    for g in custom:
        gid = str(g.get('id', ''))
        blocks.append('<div class="talk"><div class="t">' + h(g.get('name')) +
                      ' <span class="badge">自定义</span></div><div class="m">ID ' + h(gid) +
                      ' · 价格 ' + h(g.get('price', 0)) + ' G币 · 类型 ' + h(g.get('goodsType', 0)) +
                      ' · ' + h(_stamp(g.get('upStamp'))) + '</div>' +
                      '<form method="post" action="/goods/' + h(gid) + '/delete" style="margin-top:8px">' +
                      csrf_hidden() + '<button class="btn gray" type="submit">删除该商品</button></form></div>')
    form = ('<div class="box"><h2 style="margin-top:0">新增自定义商品</h2>' +
            '<div class="tip">内置 ' + str(len(seed)) + ' 件商品由服务端代码提供（清库后依然存在），不可在此删除。'
            '此处新增的商品会叠加进商城列表，客户端重进商城即可看到；购买时按填写的价格<b>真实扣除 G币</b>。</div>' +
            '<form method="post" action="/goods/add">' + csrf_hidden() +
            '<div class="frow"><label>商品名称</label><input type="text" name="name" required placeholder="如：限定皮肤"></div>' +
            '<div class="frow"><label>价格（G币）</label><input type="number" name="price" value="100" min="0"></div>' +
            '<div class="frow"><label>商品类型（数字）</label><input type="number" name="goodsType" value="1" min="0"></div>' +
            '<div class="frow"><label>图标文件名</label><input type="text" name="icon" value="demo1.png"></div>' +
            '<div style="margin-top:14px"><button class="btn" type="submit">添加商品</button></div></form></div>')
    body = ('<h1>商品管理 <span class="muted">共 ' + str(len(seed) + len(custom)) + ' 件</span></h1>' +
            '<div class="tip">商城列表 = 内置商品 + 自定义商品。客户端 <span class="mono">game_getgoodsinfos</span> / '
            '<span class="mono">game_buygoods</span> 直接读这份数据。</div>' + ''.join(blocks) + form)
    return Response(page('商品管理', body, 'goods'), mimetype='text/html; charset=utf-8')


@app.route('/goods/add', methods=['POST'])
def goods_add():
    db, ft = _feat(store.load_db())
    name = request.form.get('name', '').strip()[:40]
    if not name:
        return redirect('/goods')
    try:
        price = max(0, int(request.form.get('price', 0)))
    except Exception:
        price = 0
    try:
        gtype = max(0, int(request.form.get('goodsType', 1)))
    except Exception:
        gtype = 1
    icon = request.form.get('icon', '').strip()[:60] or 'demo1.png'
    ids = []
    for g in _lst(ft, 'goods') + _seed_goods():
        try:
            ids.append(int(g.get('id', 0)))
        except Exception:
            pass
    new_id = max(ids + [9000]) + 1
    gl = _lst(ft, 'goods')
    gl.append({'id': new_id, 'name': name, 'price': price, 'goodsType': gtype,
               'iconTextureName': icon, 'playerId': 1000001, 'saleCnt': 0,
               'upStamp': int(time.time() * 1000), 'goodsContentCnt': 1, 'advert': ''})
    ft['goods'] = gl
    _save(db, 'GOODS_ADD', '%s id=%s price=%s' % (name, new_id, price))
    return redirect('/goods')


@app.route('/goods/<gid>/delete', methods=['POST'])
def goods_delete(gid):
    db, ft = _feat(store.load_db())
    ft['goods'] = [g for g in _lst(ft, 'goods') if str(g.get('id')) != str(gid)]
    _save(db, 'GOODS_DELETE', gid)
    return redirect('/goods')


# ---- 评论 ----
@app.route('/comments')
def comments():
    db, ft = _feat(store.load_db())
    cs = _lst(ft, 'comments')
    blocks = []
    for c in cs[::-1][:120]:
        cid = str(c.get('id', ''))
        blocks.append('<div class="talk"><div class="t">#' + h(cid) + ' · ' + h(c.get('userName')) +
                      ' <span class="muted">' + h(_stamp(c.get('stamp'))) + '</span></div>' +
                      '<div class="m">目标 ' + h(c.get('_kind')) + ' / ' + h(c.get('_target')) +
                      ' · 父评论 ' + h(c.get('_parent')) + '</div>' +
                      '<div>' + h(str(c.get('content') or '')) + '</div>' +
                      '<form method="post" action="/comments/' + h(cid) + '/delete" style="margin-top:8px">' +
                      csrf_hidden() + '<button class="btn gray" type="submit">删除此评论</button></form></div>')
    if not blocks:
        blocks.append('<div class="box"><span class="muted">暂无评论。客户端在动态/作品下发表评论后会出现在这里。</span></div>')
    clear = ('<div class="box"><form method="post" action="/comments/clear">' + csrf_hidden() +
             '<button class="btn gray" type="submit">清空全部评论（' + str(len(cs)) + ' 条）</button></form></div>')
    body = ('<h1>评论管理 <span class="muted">共 ' + str(len(cs)) + ' 条</span></h1>' +
            '<div class="tip">对应客户端 <span class="mono">game_commenttalk</span> / '
            '<span class="mono">game_replytalkcomment</span> 等命令写入的数据，删除后客户端列表立即不再显示。</div>' +
            ''.join(blocks) + clear)
    return Response(page('评论管理', body, 'comments'), mimetype='text/html; charset=utf-8')


@app.route('/comments/<cid>/delete', methods=['POST'])
def comment_delete(cid):
    db, ft = _feat(store.load_db())
    ft['comments'] = [c for c in _lst(ft, 'comments') if str(c.get('id')) != str(cid)]
    _save(db, 'COMMENT_DELETE', cid)
    return redirect('/comments')


@app.route('/comments/clear', methods=['POST'])
def comments_clear():
    db, ft = _feat(store.load_db())
    n = len(_lst(ft, 'comments'))
    ft['comments'] = []
    _save(db, 'COMMENT_CLEAR', 'removed=' + str(n))
    return redirect('/comments')


# ---- 举报 ----
@app.route('/reports')
def reports():
    db, ft = _feat(store.load_db())
    rs = _lst(ft, 'reports')
    blocks = []
    for r in rs[::-1][:120]:
        rid = str(r.get('id', ''))
        done = bool(r.get('status'))
        blocks.append('<div class="talk"><div class="t">#' + h(rid) + ' · ' + h(r.get('kind')) +
                      ' 目标 ' + h(r.get('targetId')) +
                      (' <span class="badge">已处理</span>' if done else ' <span class="badge">待处理</span>') +
                      '</div><div class="m">举报人 ' + h(r.get('userName')) + ' (' + h(r.get('uid')) +
                      ') · ' + h(_stamp(r.get('stamp'))) + '</div>' +
                      '<form method="post" action="/reports/' + h(rid) + '/done" style="display:inline-block;margin-right:8px">' +
                      csrf_hidden() + '<button class="btn" type="submit">标记已处理</button></form>' +
                      '<form method="post" action="/reports/' + h(rid) + '/delete" style="display:inline-block">' +
                      csrf_hidden() + '<button class="btn gray" type="submit">删除</button></form></div>')
    if not blocks:
        blocks.append('<div class="box"><span class="muted">暂无举报记录。</span></div>')
    body = ('<h1>举报管理 <span class="muted">共 ' + str(len(rs)) + ' 条</span></h1>' +
            '<div class="tip">客户端 <span class="mono">game_reporttalk / game_reportgame / game_reportplayer</span> '
            '等命令入队。标记已处理后，「待处理举报」统计会同步更新。</div>' + ''.join(blocks))
    return Response(page('举报管理', body, 'reports'), mimetype='text/html; charset=utf-8')


@app.route('/reports/<rid>/done', methods=['POST'])
def report_done(rid):
    db, ft = _feat(store.load_db())
    for r in _lst(ft, 'reports'):
        if str(r.get('id')) == str(rid):
            r['status'] = 1
    _save(db, 'REPORT_DONE', rid)
    return redirect('/reports')


@app.route('/reports/<rid>/delete', methods=['POST'])
def report_delete(rid):
    db, ft = _feat(store.load_db())
    ft['reports'] = [r for r in _lst(ft, 'reports') if str(r.get('id')) != str(rid)]
    _save(db, 'REPORT_DELETE', rid)
    return redirect('/reports')


# ---- 互动数据 ----
@app.route('/feat')
def feat_page():
    db, ft = _feat(store.load_db())
    thumbs = _dct(ft, 'thumbs')
    follows = _dct(ft, 'follows')
    fans = _dct(ft, 'fans')
    colls = _dct(ft, 'collections')
    msgs = _lst(ft, 'msgs')
    games = _lst(ft, 'games')
    stats = ('<div class="cards">' + _card('点赞/顶踩记录', len(thumbs)) +
             _card('关注关系', sum(len(v) if isinstance(v, list) else 0 for v in follows.values())) +
             _card('粉丝关系', sum(len(v) if isinstance(v, list) else 0 for v in fans.values())) +
             _card('收藏用户', len(colls)) + _card('评论', len(_lst(ft, 'comments'))) +
             _card('举报', len(_lst(ft, 'reports'))) + _card('消息', len(msgs)) +
             _card('玩家作品', len(games)) + _card('礼物记录', len(_lst(ft, 'gifts'))) +
             _card('编辑器存档用户', len(_dct(ft, 'editor'))) + '</div>')
    mblocks = []
    for m in msgs[::-1][:15]:
        mblocks.append('<div class="talk"><div class="m">' + h(_stamp(m.get('_stamp'))) +
                       ' · 类型 ' + h(m.get('type')) + ' · ' + h(m.get('userName')) +
                       '</div><div>' + h(str(m.get('_text') or '')) + '</div></div>')
    if not mblocks:
        mblocks.append('<div class="box"><span class="muted">暂无消息通知。</span></div>')
    gblocks = []
    for g in games[::-1][:15]:
        gblocks.append('<div class="talk"><div class="t">' + h(g.get('name')) +
                       '</div><div class="m">ID ' + h(g.get('id')) + ' · ' +
                       h(_stamp(g.get('_stamp'))) + ' · 点赞 ' + h(g.get('thumbCnt', 0)) + '</div></div>')
    if not gblocks:
        gblocks.append('<div class="box"><span class="muted">暂无玩家发布的作品（内置测试作品在 agentsrv.GAMES，不在此列）。</span></div>')
    ops = ('<div class="box"><h2 style="margin-top:0">数据维护</h2>' +
           '<form method="post" action="/feat/msgs_clear" style="display:inline-block;margin-right:10px">' +
           csrf_hidden() + '<button class="btn gray" type="submit">清空消息通知</button></form>' +
           '<form method="post" action="/feat/reset" style="display:inline-block">' +
           csrf_hidden() + '<button class="btn gray" type="submit">重置全部互动数据</button></form>' +
           '<div class="muted" style="margin-top:10px">「重置全部互动数据」会清空点赞、关注/粉丝、收藏、评论、'
           '举报、消息、作品、礼物、背包、编辑器存档，<b>保留商品库与用户账号</b>。'
           '仅用于清理测试数据，客户端需重新进入对应页面刷新。</div></div>')
    body = ('<h1>互动数据</h1>' +
            '<div class="tip">这里是功能层 <span class="mono">db.json → feat</span> 的实时快照，'
            '与 WS 服务（agentsrv）共用同一份数据，此处修改后客户端立即读到。</div>' +
            stats + '<h2 class="grp">最近消息通知</h2>' + ''.join(mblocks) +
            '<h2 class="grp">玩家发布的作品</h2>' + ''.join(gblocks) + ops)
    return Response(page('互动数据', body, 'feat'), mimetype='text/html; charset=utf-8')


@app.route('/feat/msgs_clear', methods=['POST'])
def feat_msgs_clear():
    db, ft = _feat(store.load_db())
    n = len(_lst(ft, 'msgs'))
    ft['msgs'] = []
    _save(db, 'FEAT_MSGS_CLEAR', 'removed=' + str(n))
    return redirect('/feat')


@app.route('/feat/reset', methods=['POST'])
def feat_reset():
    db, ft = _feat(store.load_db())
    dict_keys = ('thumbs', 'follows', 'fans', 'newFans', 'collections', 'ranks',
                 'editor', 'inventory', 'flags', 'stats')
    list_keys = ('comments', 'msgs', 'reports', 'games', 'gifts')
    for k in dict_keys:
        ft[k] = {}
    for k in list_keys:
        ft[k] = []
    _save(db, 'FEAT_RESET')
    return redirect('/feat')


if __name__ == '__main__':
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    print('[admin] HTTPS 0.0.0.0:%d' % PORT, flush=True)
    app.run(host='0.0.0.0', port=PORT, ssl_context=ctx, threaded=True, debug=False)
