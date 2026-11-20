# 创游编辑器（私服版）客户端源码提取

一次性把 APK 里全部加密的客户端源码离线解出来，纯离线操作，不改动线上服务、不碰 App、无闪退风险。

## 成果

- **14 个 `.jsc` 全部解密成功，0 失败**，加 3 个明文 `.js`，共 **413 万字符**可读源码
- 主逻辑 `assets/main/index.e248a.js`：240 万字符 / 4.7 万行，是**格式化过的多行源码**（带真实类名、方法名、`cc._decorator`、`loadBundleRes`、`Enter("XXXScene")`），不是压缩混淆代码
- 之前靠探针 `toString()` 只能零散 dump 到 `LoginScene`、网络层；现在整份客户端逻辑都在手，包含从没被执行到的首页各 Page、消息 schema、全部业务类

## 加密方式与密钥

`.jsc` = `XXTEA(gzip(源码))` 双层：

1. **XXTEA 密钥**：`ce27dc26-f6dc-47`（16 字节），硬编码在 `lib/armeabi-v7a/libcocos2djs.so` 的 `.rodata`（偏移 17740202，前后是 `Cocos Game` / `jsb-adapter/jsb-builtin.js`，标准 Cocos 启动配置区）。`jsb_set_xxtea_key` 是导出函数，Java 层无 `setXXTEAKey` 调用，说明是 native 编译期常量。
2. **长度字**：Cocos 的 XXTEA 把原始明文长度存在解密后的最后一个 word 里（`include-length` 格式），需按此裁切。
3. **gzip**：解密后是 gzip 流（`1f8b08`），需再解压。

### 密钥是怎么找到的（可复用方法）

- 先从 APK 所有文件抽可见字符串做候选，用官方 `xxtea` 库暴力——**失败**，因为密钥虽是可见串，但正确密钥解出的是 gzip 二进制流，被"是否像 JS 文本"的判据误杀了。
- 改用**纯结构性判据**：解密后长度字必须落在 `[文件大小-7, 文件大小-4]`，对随机密钥误报率约 10⁻⁹。
- 候选从"字符串"换成**整个 `.so` 的 16 字节滑动窗口**（1 字节步进），用编译型 C 程序跑 1977 万次，几秒命中。

## 一键复现

```bash
cd 创游编辑器_源码提取
python3 extract_all.py        # 依赖: 标准库 + Python 3.x（无第三方依赖）
```

`extract_all.py` 为标准 XXTEA 纯 Python 实现 + gzip 解压，输入同目录 `app.apk`，输出到 `全部源码/`，并生成 `_manifest.txt`。密钥、路径、输出目录都在脚本顶部常量，改一处即可复用。

## 顺带定位：首页内容区空白的真正根因

> 这是之前十几轮"猜→改→重启"一直没查清的问题，现在有全量源码后一次闭合。

**启动链**（`全部源码/assets/main/index.e248a.js`）：

```
loginFlow → orangeLogin(WS连接) → roleLogin() → checkAdGM → _checkDynamic
         → Enter("HomeScene", e => e.checkPanel(a))       // 47410 行
```

关键在 `roleLogin()`（47561）和 `SendCmdAsync`（50969）：

```js
// SendCmdAsync: code==0 才解码, 否则返回 null
o = yield sendAsync(e);
if (o && 0 == o.code) return DecodeMsg(o.decBody, t);   // decBody = bon.decode(body)
else return null;

// DecodeMsg: 用消息类的默认构造 + setValue 赋值
let o = new t();  o.setValue(e);  return o;
```

`Game_RLogin`（schema 在 79307）的构造函数把每个字段都初始化成默认值：`role = new GDRole()`（空角色）、`dynamicConfig = new Map()`、`newGameDatas = []`、`followGameDatas = []`、`hotGameIdList = []`……而 `orange.DataBase.setValue`（orange.d3c22.js:696）的规则是**只赋值回包里出现了、且 schema 注册过的 key**。

我们的 `game_login` 回包 `decBody` 只有 `roleId/userId/userName/sessionId/data:{}`——**这些 key 没有一个在 `Game_RLogin` schema 里**，于是被全部静默忽略，`Game_RLogin` 保持全空默认值。

由此得出与截图完全吻合的因果链：

| 现象 | 原因 |
|---|---|
| 能登录、不闪退 | `game_login` 回包 `code:0` → `SendCmdAsync` 不返回 null → `roleLogin` 成功 |
| 底部 5 个 tab 在 | `Enter("HomeScene")` 执行了，框架 UI 正常构建 |
| 内容区全空 | `Game_RLogin` 全是默认值，`checkPanel(a)` 拿不到任何内容；首页作品列表走 `DiscoverMng` 的 **WS 指令**（`Game_GetNewGameList` 等，非 HTTP），所以 nginx 里看不到任何首页内容请求 |
| 之前日志里的 `Cannot read property ... of undefined` | 来自 `saveguide` 等其它消息类，不是登录 |

**修复方向**（有精确 schema 后不用再试错）：按 `Game_RLogin` / `GDRole` 字段表在 `game_login` 的 `decBody` 里补齐字段（尤其 `role`、`newGameDatas`、`followGameDatas`、`gameSlotUnlockLvls`、`giftCfgVersion` 等），并给 App 进首页后发出的 `Game_GetNewGameList` 系列 WS 指令加上正确响应。字段类型见 `关键代码索引.txt` 与源码 79334 / 81520 行。

## 目录

```
创游编辑器_源码提取/
├── README.md                 本文件
├── extract_all.py            一键提取脚本（纯 Python）
├── app.apk                   源 APK（32MB）
├── 关键代码索引.txt          启动链 / schema / 首页数据源 的行号索引
└── 全部源码/                 14 个解密 .js + 3 个明文 .js + _manifest.txt
    ├── assets/main/index.e248a.js   ← 游戏主逻辑（240万字符）
    ├── src/cocos2d-jsb.*.js         ← 引擎
    ├── src/assets/scripts/libs/...  ← bon / lz4 / orange / pako / png 等库
    ├── src/settings.*.js            ← 全局配置
    ├── jsb-adapter/  main.js        ← 启动引导
    └── _manifest.txt                ← 每个文件的解密前后大小
```
