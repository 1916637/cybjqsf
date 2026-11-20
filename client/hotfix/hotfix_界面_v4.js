/* PRIVSRV hotfix v4 —— 内容区可见界面（零业务依赖兜底）
 *
 * 背景：现成 DiscoverPage prefab 已能加载并挂载(hotfix.log: MAIN ADDED)，
 *   但屏幕仍全白 —— prefab 的 onLoad 依赖 role.aBTest / DynamicMng 等业务单例，
 *   服务端 game_login 回包无 role 字段，组件 onLoad 抛异常被 Cocos 吞掉，
 *   子 tab 栏 / 搜索框 / 作品列表一个都没生成。
 *
 * 本脚本绕开整条失败链：只用引擎最底层 cc.Node / cc.Label / cc.Graphics，
 *   直接挂到场景根(或 Canvas)、高 zIndex、自带自愈重画。
 *   - 不加载/实例化任何 prefab
 *   - 不读任何业务单例(DynamicMng / role / Mng)
 *   - 不覆盖任何引擎方法(p28-b 覆盖 cc.instantiate 丢 _clone 的教训)
 *   - 不遍历 window 对象树(p26 深度遍历导致 native 崩溃的教训)
 *   每一步通过 /hf 上报 UI4 *，便于从 hotfix.log 精确定位。
 * 数据写死(用户已同意"自己加测试数据")，不依赖 WS 请求，必定出画面。
 */
(function () {
  var R = window.__psrvR || function () {};
  if (window.__psrvUI4) { try { R('UI4 already'); } catch (e) {} return; }
  window.__psrvUI4 = 1;
  function S(x) { try { return String(x).replace(/\s+/g, ' ').slice(0, 150); } catch (e) { return '?'; } }
  function log(m) { try { R('UI4 ' + m); } catch (e) {} }

  var GAMES = [
    ['像素冒险', '3580 人在玩'],
    ['方块生存', '2410 人在玩'],
    ['弹幕射击', '1890 人在玩'],
    ['迷宫探秘', '1520 人在玩'],
    ['塔防物语', '1203 人在玩'],
    ['跑酷达人', '980 人在玩']
  ];
  var CARD_COLORS = [
    [255, 214, 140], [150, 208, 255], [205, 178, 255],
    [160, 228, 185], [255, 178, 178], [255, 225, 155]
  ];
  var INK = null, GRAY = null;
  try { INK = cc.color(30, 32, 40); } catch (e) { INK = null; }
  try { GRAY = cc.color(140, 144, 155); } catch (e) { GRAY = null; }

  var layer = null, ticks = 0;

  function getScene() {
    try { return cc.director.getScene(); } catch (e) { return null; }
  }
  function pickParent(scene) {
    var c = null;
    try { c = cc.find && cc.find('Canvas'); } catch (e) {}
    if (!c) { try { c = scene.getChildByName && scene.getChildByName('Canvas'); } catch (e) {} }
    return c || scene;
  }
  function mkLabel(parent, text, size, x, y, w, h, color) {
    try {
      var n = new cc.Node();
      var l = n.addComponent(cc.Label);
      l.string = text;
      l.fontSize = size;
      try { l.horizontalAlign = cc.Label.HorizontalAlign.CENTER; } catch (e) {}
      try { l.verticalAlign = cc.Label.VerticalAlign.CENTER; } catch (e) {}
      try { n.setContentSize(w, h); } catch (e) {}
      try { n.setPosition(x, y); } catch (e) {}
      if (color) { try { l.node.color = color; } catch (e) {} }
      parent.addChild(n);
    } catch (e) { log('label ERR ' + S(e && e.stack || e)); }
  }
  function rect(g, x, y, w, h, rgb) {
    try {
      g.fillColor = cc.color(rgb[0], rgb[1], rgb[2], 255);
      g.rect(x, y, w, h);
      g.fill();
    } catch (e) { log('rect ERR ' + S(e && e.stack || e)); }
  }

  function build(scene) {
    try {
    var parent = pickParent(scene);
    var cs = null, ap = null;
    try { cs = parent.getContentSize(); } catch (e) {}
    try { ap = parent.getAnchorPoint(); } catch (e) {}
    var W = (cs && cs.width) || 720, H = (cs && cs.height) || 1280;
    var ax = (ap && typeof ap.x === 'number') ? ap.x : 0.5;
    var ay = (ap && typeof ap.y === 'number') ? ap.y : 0.5;
    // 子节点局部坐标原点在父节点"锚点"处。把所有坐标统一平移到内容区中心：
    // 锚点(0.5,0.5)->偏移0；锚点(0,0)->偏移(+W/2,+H/2)。运行时实测，不猜。
    var OX = (0.5 - ax) * W, OY = (0.5 - ay) * H;
    log('build size=' + Math.round(W) + 'x' + Math.round(H) +
        ' anchor=' + ax + ',' + ay + ' off=' + Math.round(OX) + ',' + Math.round(OY) +
        ' parent=' + S(parent && parent.name));

    var left = -W / 2 + 20, right = W / 2 - 20;
    var top = H / 2 - 70, bottom = -H / 2 + 130;
    var cw = right - left;

    layer = new cc.Node('PSRV_UI4');
    parent.addChild(layer);
    try { layer.setPosition(OX, OY); } catch (e) {}
    try { layer.zIndex = 10000; } catch (e) {}

    // 一个 Graphics 画全部底板：内容区背景 / 标题栏 / tab 栏 / 6 张卡片
    var gNode = new cc.Node();
    var g = gNode.addComponent(cc.Graphics);
    layer.addChild(gNode);
    rect(g, left, bottom, cw, top - bottom, [244, 246, 251]);
    rect(g, left, top - 66, cw, 66, [255, 255, 255]);
    log('bg drawn');

    mkLabel(layer, '发现 · 推荐作品', 34, 0, top - 33, cw - 40, 60, INK);

    // 子 tab 栏（现成界面里该有的那一层）
    var tabH = 68, tabTop = top - 66 - tabH;
    rect(g, left, tabTop, cw, tabH, [255, 255, 255]);
    rect(g, left, tabTop + 6, cw / 4 - 8, 5, [250, 90, 90]);
    var tabs = ['发现', '精选', '最新', '关注'];
    for (var i = 0; i < tabs.length; i++) {
      var tx = left + cw * (i + 0.5) / 4;
      mkLabel(layer, tabs[i], 28, tx, tabTop + tabH / 2, cw / 4 - 12, 56,
              i === 0 ? INK : GRAY);
    }
    log('tabs drawn');

    // 作品卡片 2 列 × 3 行
    var gridTop = tabTop - 16, gap = 16;
    var cardW = (cw - gap * 3) / 2;
    var cardH = Math.min(150, (gridTop - bottom - gap * 4) / 3);
    if (cardH < 60) cardH = 60;
    for (var k = 0; k < GAMES.length; k++) {
      var col = k % 2, row = Math.floor(k / 2);
      var cx = left + gap + col * (cardW + gap) + cardW / 2;
      var cy = gridTop - gap - row * (cardH + gap) - cardH / 2;
      rect(g, cx - cardW / 2, cy - cardH / 2, cardW, cardH, CARD_COLORS[k]);
      mkLabel(layer, GAMES[k][0], 30, cx, cy + 18, cardW - 20, 44, INK);
      mkLabel(layer, GAMES[k][1], 22, cx, cy - 24, cardW - 20, 36, GRAY);
    }
    log('6 cards drawn; children=' + (layer.children ? layer.children.length : '?'));
    log('DONE 界面已绘制');
    } catch (e) { log('build ERR ' + S(e && e.stack || e)); layer = null; }
  }

  function alive() {
    if (!layer) return false;
    try { return !!(layer.parent && layer.activeInHierarchy !== false); }
    catch (e) { return false; }
  }

  function tick() {
    try {
      var scene = getScene();
      if (scene && !alive()) build(scene);
      else if (scene && ticks % 20 === 0) log('alive t=' + ticks + ' scene=' + S(scene.name));
    } catch (e) { log('tick ERR ' + S(e && e.stack || e)); }
    if (++ticks < 500) setTimeout(tick, 800);
    else log('stop polling');
  }

  log('start cc=' + (typeof cc) + ' dir=' + (window.cc && cc.director ? 'yes' : 'no'));
  setTimeout(tick, 300);
})();
