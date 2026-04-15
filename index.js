'use strict';
require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const tls = require('tls');
const https = require('https');
const net = require('net');
const dns = require('dns').promises;
const { Pool } = require('pg');

// V2.5：爬蟲模組（如果存在）
let crawler = null;
try {
  crawler = require('./crawler');
  console.log('✅ 爬蟲模組載入成功');
} catch (e) {
  console.log('⚠️ 爬蟲模組未載入（crawler.js 不存在）');
}

const app = express();

// P1-03：Trust proxy 設定（Railway 是單層 reverse proxy）
// 啟用後 req.ip 會正確解析 X-Forwarded-For，而非被偽造
app.set('trust proxy', 1);

// ════════════════════════════════════════
// V2.5：PostgreSQL 連線
// ════════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false,
  max: 10,                // 最大連線數
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// DB 健康狀態追蹤
let dbHealthy = false;

// 測試連線
pool.query('SELECT NOW()')
  .then(() => { dbHealthy = true; console.log('✅ PostgreSQL 連線成功'); })
  .catch(err => console.log('⚠️ PostgreSQL 連線失敗，使用記憶體模式：', err.message));

// P1-07：DB 連線事件監聯
pool.on('error', (err) => {
  dbHealthy = false;
  console.error(JSON.stringify({ event: 'db_pool_error', error: err.message, timestamp: new Date().toISOString() }));
});

// DB 輔助函式
// P1-07：structured logging，不再靜默吞錯
async function dbQuery(text, params) {
  try {
    const result = await pool.query(text, params);
    if (!dbHealthy) { dbHealthy = true; console.log('[DB] 連線恢復'); }
    return result;
  } catch (err) {
    dbHealthy = false;
    console.error(JSON.stringify({
      event: 'db_query_error',
      query: text.slice(0, 100),
      error: err.message,
      timestamp: new Date().toISOString(),
    }));
    return null;
  }
}

// 取得或建立 domain ID
async function getOrCreateDomainId(domain) {
  try {
    // 先查詢
    let result = await pool.query(
      'SELECT id FROM domains WHERE domain = $1',
      [domain]
    );
    if (result.rows.length > 0) {
      return result.rows[0].id;
    }
    // 不存在則建立
    result = await pool.query(
      'INSERT INTO domains (domain) VALUES ($1) ON CONFLICT (domain) DO UPDATE SET updated_at = NOW() RETURNING id',
      [domain]
    );
    return result.rows[0].id;
  } catch (err) {
    console.error('getOrCreateDomainId Error:', err.message);
    return null;
  }
}

// ════════════════════════════════════════
// 安全防護措施
// ════════════════════════════════════════

// ── 1. CORS 嚴格限制 ──
// 只允許來自官網和 Chrome 擴充套件的請求
const ALLOWED_ORIGINS = [
  'https://trustint.org',
  'https://www.trustint.org',
  'https://trustint.tw',
  'https://www.trustint.tw',
  'https://trustint-production.up.railway.app',
  'http://localhost:3000',  // 本機開發用
];

// Chrome 擴充套件 ID（上架後填入真實 ID）
const ALLOWED_EXTENSION_IDS = [
  // 'chrome-extension://你的擴充套件ID',
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    // Chrome 擴充套件
    if (origin.startsWith('chrome-extension://')) {
      if (ALLOWED_EXTENSION_IDS.length > 0 && ALLOWED_EXTENSION_IDS.includes(origin)) {
        return callback(null, true);
      }
      // P1-02：未上架前仍放行但記錄（上架後務必填入真實 ID 並移除此 fallback）
      console.log(`[CORS] 未驗證的擴充套件: ${origin}`);
      return callback(null, true);
    }
    // 白名單域名
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    // trustint.org 及其子域名
    if (origin === 'https://trustint.org' || origin.endsWith('.trustint.org')) return callback(null, true);
    return callback(new Error('CORS blocked'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  credentials: false,
}));

// ── 2. Rate Limiting（流量限制）──
// 同一 IP 每分鐘最多 30 次查詢，防止惡意爬蟲
const rateLimitMap = new Map();

function rateLimiter(req, res, next) {
  // P1-03：trust proxy 設定後，req.ip 會正確解析，不再手動讀 header
  const ip = req.ip;
  
  // 本機測試不限流
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip === 'localhost') {
    return next();
  }
  
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 分鐘
  const maxRequests = 30;

  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
    return next();
  }

  const record = rateLimitMap.get(ip);
  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + windowMs;
    return next();
  }

  record.count++;
  if (record.count > maxRequests) {
    res.set('Retry-After', Math.ceil((record.resetTime - now) / 1000));
    return res.status(429).json({
      status: 'error',
      message: '查詢過於頻繁，請稍後再試。每分鐘最多 30 次查詢。'
    });
  }
  next();
}

// 每 5 分鐘清理過期的 rate limit 紀錄
setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of rateLimitMap) {
    if (now > record.resetTime + 60000) rateLimitMap.delete(ip);
  }
}, 5 * 60 * 1000);

// 對 API 路由套用 rate limiting
app.use('/v1/', rateLimiter);

// ── 6. 統計計數器（儀表板用）──
const stats = {
  totalChecks: 0,        // 總查詢次數
  totalDeepAnalyzes: 0,  // 深度分析次數
  totalBlocks: 0,        // 攔截次數（L4+L5）
  todayChecks: 0,        // 今日查詢
  todayBlocks: 0,        // 今日攔截
  todayDate: new Date().toISOString().split('T')[0],
  uniqueIPs: new Set(),  // 獨立 IP（估算用戶數）
  levelCounts: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 },
};

// 每日重置今日計數
setInterval(() => {
  const today = new Date().toISOString().split('T')[0];
  if (today !== stats.todayDate) {
    // P1-04：先觸發每日摘要儲存（使用昨日數據）
    saveDailySummary();
    // 重置所有每日計數
    stats.todayChecks = 0;
    stats.todayBlocks = 0;
    stats.uniqueIPs = new Set();  // P1-04：每日重置，防止無限增長
    stats.levelCounts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };  // P1-04：每日重置
    stats.todayDate = today;
  }
}, 60 * 1000);

// 記錄查詢的中介層
// P2-06：改用 response header 追蹤，不再 monkey-patch res.json
function trackStats(req, res, next) {
  const ip = req.ip;
  stats.uniqueIPs.add(ip);
  
  if (req.path === '/v1/check') {
    stats.totalChecks++;
    stats.todayChecks++;
  } else if (req.path === '/v1/deep-analyze') {
    stats.totalDeepAnalyzes++;
    stats.totalChecks++;
    stats.todayChecks++;
  }
  
  // P2-06：在 response 結束後透過自訂 header 記錄等級
  // 各路由在回應前設定 res.locals.trustintLevel，這裡統一計數
  res.on('finish', () => {
    const level = res.locals.trustintLevel;
    if (level) {
      stats.levelCounts[level] = (stats.levelCounts[level] || 0) + 1;
      if (level >= 4) {
        stats.totalBlocks++;
        stats.todayBlocks++;
      }
    }
  });
  next();
}
app.use('/v1/', trackStats);

// 統計 API（公開，儀表板用）
app.get('/v1/stats', (req, res) => {
  res.json({
    status: 'ok',
    stats: {
      total_checks: stats.totalChecks,
      total_deep_analyzes: stats.totalDeepAnalyzes,
      total_blocks: stats.totalBlocks,
      today_checks: stats.todayChecks,
      today_blocks: stats.todayBlocks,
      protected_users: stats.uniqueIPs.size,
      level_distribution: stats.levelCounts,
      blacklist_size: {
        npa_165: npaBlacklist.size,
        openphish: openPhishList.size,
        majestic: majesticList.size,
      },
      uptime_hours: Math.floor(process.uptime() / 3600),
    }
  });
});

// ── 3. 安全 Headers ──
app.use((req, res, next) => {
  // 防止被 iframe 嵌入（防點擊劫持）
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  // 防止 MIME 類型嗅探
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // XSS 防護
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Referrer 政策
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // 禁止搜尋引擎快取 API 回應
  if (req.path.startsWith('/v1/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache');
  }
  next();
});

// ── 4. 圖片防盜鏈（Hotlink Protection）──
app.use('/images', (req, res, next) => {
  const referer = req.headers.referer || req.headers.referrer || '';
  // 允許無 referer（直接訪問）和允許的來源
  if (!referer) return next();
  try {
    const refHost = new URL(referer).hostname;
    const allowed = [
      'trustint.org', 'www.trustint.org',
      'trustint.tw', 'www.trustint.tw',
      'trustint-production.up.railway.app',
      'localhost',
    ];
    if (allowed.some(h => refHost === h || refHost.endsWith('.' + h))) {
      return next();
    }
  } catch {}
  // 盜鏈請求：回傳 403
  return res.status(403).json({ status: 'error', message: 'Hotlink not allowed' });
});

// ── 5. 靜態檔案防護 ──
// 對 HTML 頁面加入右鍵保護和複製保護的 meta（前端層防護）
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    // 圖片設定短快取 + 防盜鏈 header
    if (filePath.match(/\.(png|jpg|jpeg|gif|svg|webp|ico)$/i)) {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    }
    // HTML 不快取
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// ════════════════════════════════════════════════════════════════
//  TrustInt 威脅分析引擎 v2.4
//  P0→P6 完整決策流程
//  v2.4 新增：BHR-OV 憑證主體驗證（V1-09）、SSL 憑證完整檢查
//  v2.3.1 新增：DOM-Lite 整合（ATK-1）、Unicode Confusable（ATK-3）、
//              BHR9 擴充（ATK-9）、BHR17 寄生平台社交誘導、
//              新站群5保護（ATK-6）、FP/FN 回報系統強化
//  由一位國營銀行的小小銀行員，與 AI 大哥一起建立 🛡️
// ════════════════════════════════════════════════════════════════

// ════════════════════════════════════════
// 黑白名單快取
// ════════════════════════════════════════
let openPhishList = new Set();
let majesticList  = new Set();
let npaBlacklist  = new Set();
let npaIpSubnets  = new Set();

// P2-05：黑名單健康狀態追蹤
const blacklistHealth = {
  openphish: { loaded: false, size: 0, lastSuccess: null, lastError: null, retryCount: 0 },
  majestic:  { loaded: false, size: 0, lastSuccess: null, lastError: null, retryCount: 0 },
  npa:       { loaded: false, size: 0, lastSuccess: null, lastError: null, retryCount: 0 },
};

// ════════════════════════════════════════
// v2.3.1：結果快取（V1-15 實作）
// 節省 API 額度，並為 L2 定期重掃提供基礎
// ════════════════════════════════════════
const resultCache = new Map();  // domain -> { level, label, timestamp, ttl }
const CACHE_TTL = {
  L1: 7 * 24 * 60 * 60 * 1000,   // L1 官方驗證：7 天
  L2: 24 * 60 * 60 * 1000,        // L2 安心信任：1 天（v3.0 安全修正：從 3 天縮短）
  L3: 6 * 60 * 60 * 1000,         // L3 未知：6 小時（v3.0 安全修正：從 1 天縮短）
  L4: 1 * 60 * 60 * 1000,         // L4 極高風險：1 小時（v3.0 安全修正：從 7 天縮短，詐騙站可能隨時下線）
  L5: 1 * 60 * 60 * 1000,         // L5 多項異常：1 小時（同上）
};
const MAX_CACHE_SIZE = 10000;

function getCachedResult(domain) {
  const cached = resultCache.get(domain);
  if (!cached) return null;
  
  const now = Date.now();
  const ttl = CACHE_TTL[`L${cached.level}`] || CACHE_TTL.L3;
  
  if (now - cached.timestamp > ttl) {
    resultCache.delete(domain);
    return null;
  }
  
  return cached;
}

function setCachedResult(domain, level, label, riskScore = 0) {
  // P1-05：改用 Map insertion order 清理，避免同步排序阻塞 event loop
  if (resultCache.size >= MAX_CACHE_SIZE) {
    let count = 0;
    for (const key of resultCache.keys()) {
      if (count >= 1000) break;
      resultCache.delete(key);
      count++;
    }
  }
  
  resultCache.set(domain, {
    level,
    label,
    riskScore,
    timestamp: Date.now(),
  });
}

// 每小時清理過期快取
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [domain, cached] of resultCache) {
    const ttl = CACHE_TTL[`L${cached.level}`] || CACHE_TTL.L3;
    if (now - cached.timestamp > ttl) {
      resultCache.delete(domain);
      cleaned++;
    }
  }
  if (cleaned > 0) console.log(`🧹 清理過期快取：${cleaned} 筆`);
}, 60 * 60 * 1000);

// ════════════════════════════════════════
// v2.4：SSL 憑證檢查（V1-09 BHR-OV 實作）
// 取得憑證類型（DV/OV/EV）和組織名稱
// ════════════════════════════════════════
async function checkSSLCertificate(domain) {
  return new Promise((resolve) => {
    const result = {
      hasHttps: false,
      certType: 'unknown',
      certOrg: null,        // 憑證的 Organization 欄位
      certIssuer: null,     // 憑證簽發機構
      certAgeDays: null,    // 憑證已簽發天數
      certValidDays: null,  // 憑證剩餘有效天數
    };

    const options = {
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,  // 允許自簽憑證（我們只是檢查，不驗證）
      timeout: 5000,
    };

    const socket = tls.connect(options, () => {
      try {
        const cert = socket.getPeerCertificate();
        
        if (cert && Object.keys(cert).length > 0) {
          result.hasHttps = true;
          
          // 取得憑證組織資訊
          if (cert.subject) {
            result.certOrg = cert.subject.O || null;  // Organization
          }
          
          // 取得簽發機構
          if (cert.issuer) {
            result.certIssuer = cert.issuer.O || cert.issuer.CN || null;
          }
          
          // 計算憑證年齡（從 validFrom 到現在）
          if (cert.valid_from) {
            const validFrom = new Date(cert.valid_from);
            const now = new Date();
            result.certAgeDays = Math.floor((now - validFrom) / (1000 * 60 * 60 * 24));
          }
          
          // 計算剩餘有效天數
          if (cert.valid_to) {
            const validTo = new Date(cert.valid_to);
            const now = new Date();
            result.certValidDays = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
          }
          
          // 判斷憑證類型
          // EV 憑證通常有 businessCategory 或特定 OID
          // OV 憑證有 Organization (O) 欄位
          // DV 憑證通常只有 CN，沒有 O
          if (cert.subject && cert.subject.businessCategory) {
            result.certType = 'EV';
          } else if (cert.subject && cert.subject.O && cert.subject.O.length > 0) {
            // 有 Organization 欄位，可能是 OV 或 EV
            // 進一步檢查是否有國家/州等資訊（OV/EV 通常有）
            if (cert.subject.L || cert.subject.ST || cert.subject.C) {
              result.certType = 'OV';
            } else {
              // 只有 O，可能是某些 CA 的 DV 憑證
              result.certType = 'OV';  // 保守判斷為 OV
            }
          } else {
            result.certType = 'DV';
          }
        }
      } catch (err) {
        // 解析錯誤，保持預設值
      }
      
      socket.end();
      resolve(result);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(result);  // 連線失敗，回傳預設值
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(result);
    });
  });
}

// ════════════════════════════════════════
// v2.4：BHR-OV 品牌憑證驗證（V1-09）
// 檢查 OV/EV 憑證的組織名稱是否與聲稱品牌一致
// ════════════════════════════════════════
const BRAND_CERT_MAPPING = {
  // 台灣銀行
  'bot.com.tw': ['台灣銀行', 'Bank of Taiwan', 'BANK OF TAIWAN'],
  'landbank.com.tw': ['臺灣土地銀行', 'Land Bank of Taiwan'],
  'esunbank.com.tw': ['玉山銀行', 'E.SUN COMMERCIAL BANK', 'E.SUN'],
  'ctbcbank.com': ['中國信託', 'CTBC Bank', 'CTBC FINANCIAL'],
  'cathaybank.com': ['國泰世華', 'Cathay United Bank'],
  'cathaybk.com.tw': ['國泰世華', 'Cathay United Bank'],
  'fubon.com': ['富邦', 'Fubon'],
  'taishinbank.com.tw': ['台新銀行', 'Taishin Bank'],
  'sinopac.com': ['永豐銀行', 'SinoPac', 'BANK SINOPAC'],
  'megabank.com.tw': ['兆豐銀行', 'Mega Bank', 'MEGA INTERNATIONAL'],
  'firstbank.com.tw': ['第一銀行', 'First Commercial Bank', 'FIRST BANK'],
  'hncb.com.tw': ['華南銀行', 'Hua Nan Bank', 'HUA NAN COMMERCIAL'],
  
  // 電商
  'shopee.tw': ['蝦皮', 'Shopee', 'SEA LIMITED'],
  'momoshop.com.tw': ['富邦媒體科技', 'momo', 'MOMO.COM'],
  'pchome.com.tw': ['PChome', 'PCHOME ONLINE'],
  
  // 科技
  'google.com': ['Google', 'GOOGLE LLC', 'GOOGLE INC'],
  'apple.com': ['Apple', 'APPLE INC'],
  'microsoft.com': ['Microsoft', 'MICROSOFT CORPORATION'],
  'facebook.com': ['Meta', 'Facebook', 'META PLATFORMS'],
  
  // 電信
  'cht.com.tw': ['中華電信', 'Chunghwa Telecom', 'CHUNGHWA TELECOM'],
  'fetnet.net': ['遠傳電信', 'Far EasTone', 'FAR EASTONE'],
  'taiwanmobile.com': ['台灣大哥大', 'Taiwan Mobile', 'TAIWAN MOBILE'],
};

function checkBHROV(domain, certOrg, certType, pageTitle = '') {
  // 只有 OV 或 EV 憑證才檢查
  if (certType !== 'OV' && certType !== 'EV') {
    return null;
  }
  
  // 如果沒有憑證組織資訊，無法檢查
  if (!certOrg) {
    return null;
  }
  
  // 檢查頁面是否聲稱是某個品牌
  const claimedBrand = detectClaimedBrand(domain, pageTitle);
  if (!claimedBrand) {
    return null;  // 沒有聲稱品牌，不觸發
  }
  
  // 取得該品牌的合法憑證組織名稱
  const validOrgs = BRAND_CERT_MAPPING[claimedBrand.officialDomain];
  if (!validOrgs) {
    return null;  // 沒有該品牌的憑證對照表
  }
  
  // 檢查憑證組織是否匹配
  const certOrgUpper = certOrg.toUpperCase();
  const isMatch = validOrgs.some(org => 
    certOrgUpper.includes(org.toUpperCase())
  );
  
  if (!isMatch) {
    return {
      triggered: true,
      code: 'BHR-OV',
      desc: `OV/EV 憑證主體不符：聲稱 ${claimedBrand.brand}，憑證組織為 ${certOrg}`,
      confidence: 0.95,
      level: 5
    };
  }
  
  return null;
}

function detectClaimedBrand(domain, pageTitle) {
  // 檢查域名或頁面標題是否聲稱是某個品牌
  const domainLower = domain.toLowerCase();
  const titleLower = (pageTitle || '').toLowerCase();
  
  const brandPatterns = [
    { pattern: /esun|玉山/, brand: '玉山銀行', officialDomain: 'esunbank.com.tw' },
    { pattern: /ctbc|中國信託|中信/, brand: '中國信託', officialDomain: 'ctbcbank.com' },
    { pattern: /cathay|國泰/, brand: '國泰世華', officialDomain: 'cathaybk.com.tw' },
    { pattern: /fubon|富邦/, brand: '富邦', officialDomain: 'fubon.com' },
    { pattern: /taishin|台新/, brand: '台新銀行', officialDomain: 'taishinbank.com.tw' },
    { pattern: /sinopac|永豐/, brand: '永豐銀行', officialDomain: 'sinopac.com' },
    { pattern: /mega|兆豐/, brand: '兆豐銀行', officialDomain: 'megabank.com.tw' },
    { pattern: /first.?bank|第一銀行/, brand: '第一銀行', officialDomain: 'firstbank.com.tw' },
    { pattern: /shopee|蝦皮/, brand: '蝦皮購物', officialDomain: 'shopee.tw' },
    { pattern: /momo|富邦媒體/, brand: 'momo購物', officialDomain: 'momoshop.com.tw' },
    { pattern: /pchome/, brand: 'PChome', officialDomain: 'pchome.com.tw' },
    { pattern: /google/, brand: 'Google', officialDomain: 'google.com' },
    { pattern: /apple/, brand: 'Apple', officialDomain: 'apple.com' },
    { pattern: /microsoft/, brand: 'Microsoft', officialDomain: 'microsoft.com' },
    { pattern: /facebook|meta/, brand: 'Facebook', officialDomain: 'facebook.com' },
  ];
  
  for (const { pattern, brand, officialDomain } of brandPatterns) {
    // 不檢查官方域名本身
    if (domainLower.includes(officialDomain.split('.')[0])) {
      // 確認是不是真正的官方域名
      if (domainLower === officialDomain || domainLower.endsWith('.' + officialDomain)) {
        return null;  // 是官方域名，不需要檢查
      }
    }
    
    if (pattern.test(domainLower) || pattern.test(titleLower)) {
      return { brand, officialDomain };
    }
  }
  
  return null;
}

async function loadOpenPhish() {
  try {
    const res = await axios.get('https://openphish.com/feed.txt', { timeout: 10000 });
    openPhishList = new Set();
    res.data.split('\n').filter(l => l.trim()).forEach(url => {
      try { openPhishList.add(new URL(url.trim()).hostname); } catch {}
    });
    blacklistHealth.openphish = { loaded: true, size: openPhishList.size, lastSuccess: new Date().toISOString(), lastError: null, retryCount: 0 };
    console.log(`✅ OpenPhish 載入：${openPhishList.size} 筆`);
  } catch (e) {
    blacklistHealth.openphish.lastError = e.message;
    blacklistHealth.openphish.retryCount++;
    console.error(`🔴 OpenPhish 載入失敗（第 ${blacklistHealth.openphish.retryCount} 次）：${e.message}`);
    // P2-05：指數退避 retry（最多 5 次，最長 5 分鐘）
    if (blacklistHealth.openphish.retryCount <= 5) {
      const delay = Math.min(60000 * Math.pow(2, blacklistHealth.openphish.retryCount - 1), 300000);
      setTimeout(loadOpenPhish, delay);
    }
  }
}

// v3.0：Majestic 過濾黑名單（載入時排除可疑域名）
const MAJESTIC_BLOCK_KEYWORDS = [
  'casino', 'poker', 'slot', 'bet', 'betting', 'gambl', 'lottery',
  'porn', 'xxx', 'sex', 'adult', 'nude', 'hentai',
  'weed', 'cannabis', 'crack',
  '娛樂城', '博弈', '賭', '老虎機', '百家樂', '運彩',
];

// v3.0：高風險關鍵字（不阻擋但警示）
const WARNING_KEYWORDS = {
  gambling: ['casino', 'poker', 'slot', 'bet365', 'betting', 'gambl', 'lottery',
    '娛樂城', '博弈', '賭場', '老虎機', '百家樂', '運彩', '線上賭', '真人荷官',
    'baccarat', 'roulette', 'blackjack', 'sportsbook'],
  adult: ['porn', 'xxx', 'sex', 'adult', 'nude', 'hentai', 'escort',
    '成人', '色情', 'nsfw'],
  crypto_risk: ['crypto-airdrop', 'free-bitcoin', 'mining-pool', 'doubler',
    '挖礦', '空投', '免費幣'],
};

function detectWarningKeywords(domain, title = '', bodyText = '') {
  const combined = (domain + ' ' + title + ' ' + bodyText).toLowerCase();
  const warnings = [];
  for (const [category, keywords] of Object.entries(WARNING_KEYWORDS)) {
    const matched = keywords.filter(k => combined.includes(k));
    if (matched.length >= 1) {
      warnings.push({ category, matched: matched.slice(0, 3) });
    }
  }
  return warnings;
}

async function loadMajestic() {
  try {
    const res = await axios.get('https://downloads.majestic.com/majestic_million.csv', { timeout: 30000 });
    majesticList = new Set();
    let blocked = 0;
    res.data.split('\n').slice(1, 50001).forEach(line => {
      const p = line.split(',');
      if (p[2]) {
        const domain = p[2].trim().toLowerCase();
        const isBlocked = MAJESTIC_BLOCK_KEYWORDS.some(k => domain.includes(k));
        if (!isBlocked) {
          majesticList.add(domain);
        } else {
          blocked++;
        }
      }
    });
    blacklistHealth.majestic = { loaded: true, size: majesticList.size, lastSuccess: new Date().toISOString(), lastError: null, retryCount: 0 };
    console.log(`✅ Majestic Million 載入：${majesticList.size} 筆（過濾 ${blocked} 筆可疑域名）`);
  } catch (e) {
    blacklistHealth.majestic.lastError = e.message;
    blacklistHealth.majestic.retryCount++;
    console.error(`🔴 Majestic 載入失敗（第 ${blacklistHealth.majestic.retryCount} 次）：${e.message}`);
    if (blacklistHealth.majestic.retryCount <= 5) {
      const delay = Math.min(60000 * Math.pow(2, blacklistHealth.majestic.retryCount - 1), 300000);
      setTimeout(loadMajestic, delay);
    }
  }
}

function loadNPABlacklist() {
  try {
    const files = [
      path.join(__dirname, 'data/npa_blacklist.csv'),
      path.join(__dirname, 'data/npa_blacklist2.csv')
    ];
    const domains = new Set();
    for (const file of files) {
      if (!fs.existsSync(file)) continue;
      const raw = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
      const skipLines = file.includes('npa_blacklist2') ? 1 : 2;
      const lines = raw.split('\n').slice(skipLines);
      lines.forEach(line => {
        const parts = line.split(',');
        if (parts[1]) {
          const d = parts[1].trim().toLowerCase().replace(/^www\./, '').replace(/\r/g, '');
          if (d) domains.add(d);
        }
      });
    }
    npaBlacklist = domains;
    blacklistHealth.npa = { loaded: true, size: npaBlacklist.size, lastSuccess: new Date().toISOString(), lastError: null, retryCount: 0 };
    console.log(`✅ 165 黑名單載入：${npaBlacklist.size} 筆`);
  } catch (e) {
    blacklistHealth.npa.lastError = e.message;
    console.error(`🔴 165 黑名單載入失敗：${e.message}`);
  }
}

// v3.0：165 Open Data API 自動同步（每 6 小時更新）
// 來源：政府開放資料平台 + 內政部 Open Data
const NPA_OPEN_DATA_URLS = [
  // 假投資/博弈詐騙網站
  'https://od.moi.gov.tw/api/v1/rest/datastore/A01010000C-002150-005',
  // 你提供的另一個端點
  'https://opdadm.moi.gov.tw/api/v1/no-auth/resource/api/dataset/033197D4-70F4-45EB-9FB8-6D83532B999A/resource/FEAA1683-4483-4FDC-B861-BC530789E2AB/download',
];

async function loadNPA165OpenData() {
  let totalAdded = 0;
  const beforeSize = npaBlacklist.size;

  for (const url of NPA_OPEN_DATA_URLS) {
    try {
      const res = await axios.get(url, { timeout: 30000 });
      const data = res.data;
      let added = 0;

      // 格式 1：JSON API（od.moi.gov.tw）
      if (typeof data === 'object' && data.result && data.result.records) {
        for (const record of data.result.records) {
          // 欄位可能是 WEBURL、網址、url 等
          const rawUrl = record.WEBURL || record['網址'] || record.url || record.website || '';
          const domain = extractDomain(rawUrl);
          if (domain && !npaBlacklist.has(domain)) {
            npaBlacklist.add(domain);
            added++;
          }
        }
      }
      // 格式 2：CSV（opdadm.moi.gov.tw）
      else if (typeof data === 'string' && data.includes(',')) {
        const lines = data.split('\n').slice(1); // 跳過標題
        for (const line of lines) {
          const parts = line.split(',');
          // 嘗試每個欄位找域名
          for (const part of parts) {
            const cleaned = part.trim().replace(/"/g, '');
            if (cleaned.includes('.') && !cleaned.includes(' ') && cleaned.length > 3) {
              const domain = extractDomain(cleaned);
              if (domain && !npaBlacklist.has(domain)) {
                npaBlacklist.add(domain);
                added++;
              }
            }
          }
        }
      }
      // 格式 3：JSON 但整個是陣列
      else if (Array.isArray(data)) {
        for (const item of data) {
          const rawUrl = item.WEBURL || item['網址'] || item.url || item.website || '';
          const domain = extractDomain(rawUrl);
          if (domain && !npaBlacklist.has(domain)) {
            npaBlacklist.add(domain);
            added++;
          }
        }
      }

      if (added > 0) {
        console.log(`✅ 165 Open Data 載入 ${added} 筆（來源: ${url.split('/').pop().slice(0, 30)}）`);
        totalAdded += added;
      }
    } catch (e) {
      console.error(`⚠️ 165 Open Data 失敗（${url.split('/').pop().slice(0, 20)}）：${e.message}`);
    }
  }

  if (totalAdded > 0) {
    blacklistHealth.npa.size = npaBlacklist.size;
    blacklistHealth.npa.lastSuccess = new Date().toISOString();
    console.log(`✅ 165 Open Data 同步完成：新增 ${totalAdded} 筆（總計 ${npaBlacklist.size}，原 ${beforeSize}）`);
  }

  // v3.0.1：黑名單上限保護（防止長期累積導致 OOM）
  // 165 黑名單正常不會超過 200,000 筆，超過代表有異常
  if (npaBlacklist.size > 200000) {
    console.log(`[WARN] npaBlacklist 超過 200,000 筆（${npaBlacklist.size}），可能有異常資料`);
  }
}

// 從各種格式的 URL/文字中提取域名
function extractDomain(input) {
  if (!input || typeof input !== 'string') return null;
  let cleaned = input.trim().toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .replace(/\r|\n/g, '');
  // 驗證看起來像域名
  if (cleaned && cleaned.includes('.') && cleaned.length > 3 && cleaned.length < 200 &&
      !cleaned.includes(' ') && !cleaned.includes(',')) {
    return cleaned;
  }
  return null;
}

loadOpenPhish();
loadMajestic();
loadNPABlacklist();
// 165 Open Data：啟動 10 秒後首次載入，之後每 6 小時同步
setTimeout(loadNPA165OpenData, 10000);
setInterval(loadNPA165OpenData, 6 * 60 * 60 * 1000);

setInterval(loadOpenPhish, 60 * 60 * 1000);
setInterval(loadMajestic,  24 * 60 * 60 * 1000);

// ════════════════════════════════════════
// 工具函式
// ════════════════════════════════════════

// v3.0.1：extractDomain 已定義在上方（165 Open Data 區塊），此處不再重複定義

function decodePunycode(domain) {
  try {
    if (!domain.includes('xn--')) return domain;
    return require('url').domainToUnicode(domain);
  } catch { return domain; }
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] :
        1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq)
    .map(f => f / len)
    .reduce((sum, p) => sum + p * Math.log2(p), 0);
}

// v2.3：Jaro-Winkler 相似度（對前綴敏感，補充 Levenshtein 的不足）
function jaroWinkler(s1, s2) {
  if (s1 === s2) return 1.0;
  const len1 = s1.length, len2 = s2.length;
  if (len1 === 0 || len2 === 0) return 0.0;
  const matchDist = Math.floor(Math.max(len1, len2) / 2) - 1;
  const s1Matches = new Array(len1).fill(false);
  const s2Matches = new Array(len2).fill(false);
  let matches = 0, transpositions = 0;
  for (let i = 0; i < len1; i++) {
    const start = Math.max(0, i - matchDist);
    const end = Math.min(i + matchDist + 1, len2);
    for (let j = start; j < end; j++) {
      if (s2Matches[j] || s1[i] !== s2[j]) continue;
      s1Matches[i] = true; s2Matches[j] = true;
      matches++; break;
    }
  }
  if (matches === 0) return 0.0;
  let k = 0;
  for (let i = 0; i < len1; i++) {
    if (!s1Matches[i]) continue;
    while (!s2Matches[k]) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }
  const jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3;
  let prefix = 0;
  for (let i = 0; i < Math.min(4, Math.min(len1, len2)); i++) {
    if (s1[i] === s2[i]) prefix++; else break;
  }
  return jaro + prefix * 0.1 * (1 - jaro);
}

// ════════════════════════════════════════
// v2.3.1：Unicode Confusable 正規化（ATK-3 防禦）
// 根據 Unicode TR39 Confusable Mapping
// ════════════════════════════════════════
const CONFUSABLE_MAP = {
  // ═══ Cyrillic → Latin ═══
  'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P',
  'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
  'Ѕ': 'S', 'І': 'I', 'Ј': 'J', 'ј': 'j', 'һ': 'h', 'Ү': 'Y', 'ү': 'y',
  'ғ': 'f', 'ҝ': 'k', 'ҩ': 'o', 'Ғ': 'F', 'Қ': 'K',
  // ═══ Greek → Latin ═══
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
  'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
  'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Υ': 'Y', 'Ζ': 'Z',
  // ═══ 全形 → 半形 ═══
  '０': '0', '１': '1', '２': '2', '３': '3', '４': '4', '５': '5',
  '６': '6', '７': '7', '８': '8', '９': '9',
  'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g',
  'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n',
  'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't', 'ｕ': 'u',
  'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
  'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F', 'Ｇ': 'G',
  'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J', 'Ｋ': 'K', 'Ｌ': 'L', 'Ｍ': 'M', 'Ｎ': 'N',
  'Ｏ': 'O', 'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R', 'Ｓ': 'S', 'Ｔ': 'T', 'Ｕ': 'U',
  'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X', 'Ｙ': 'Y', 'Ｚ': 'Z',
  // ═══ 特殊 Latin 變體 ═══
  'ı': 'i', 'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɪ': 'i', 'ʏ': 'y', 'ʝ': 'j',
  'ʀ': 'r', 'ʙ': 'b', 'ᴀ': 'a', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ᴊ': 'j',
  'ᴋ': 'k', 'ᴍ': 'm', 'ᴏ': 'o', 'ᴘ': 'p', 'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v',
  'ᴡ': 'w', 'ᴢ': 'z', 'ᵃ': 'a', 'ᵇ': 'b', 'ᵈ': 'd', 'ᵉ': 'e', 'ᵍ': 'g',
  'ᵏ': 'k', 'ᵐ': 'm', 'ᵒ': 'o', 'ᵖ': 'p', 'ᵗ': 't', 'ᵘ': 'u', 'ᵛ': 'v',
  // ═══ 羅馬數字 ═══
  'ⅰ': 'i', 'ⅱ': 'ii', 'ⅲ': 'iii', 'ⅳ': 'iv', 'ⅴ': 'v', 'ⅵ': 'vi',
  'ⅶ': 'vii', 'ⅷ': 'viii', 'ⅸ': 'ix', 'ⅹ': 'x', 'ⅺ': 'xi', 'ⅻ': 'xii',
  'ⅼ': 'l', 'ⅽ': 'c', 'ⅾ': 'd', 'ⅿ': 'm',
  'Ⅰ': 'I', 'Ⅱ': 'II', 'Ⅲ': 'III', 'Ⅳ': 'IV', 'Ⅴ': 'V', 'Ⅵ': 'VI',
  'Ⅶ': 'VII', 'Ⅷ': 'VIII', 'Ⅸ': 'IX', 'Ⅹ': 'X', 'Ⅺ': 'XI', 'Ⅻ': 'XII',
  'Ⅼ': 'L', 'Ⅽ': 'C', 'Ⅾ': 'D', 'Ⅿ': 'M',
  // ═══ 數學/特殊符號 ═══
  'ℓ': 'l', '℮': 'e', 'ℕ': 'N', 'ℙ': 'P', 'ℚ': 'Q', 'ℝ': 'R', 'ℤ': 'Z',
  'ℂ': 'C', 'ℍ': 'H', 'ℐ': 'I', 'ℒ': 'L', 'ℳ': 'M', 'ℛ': 'R', 'ℬ': 'B',
  'ℰ': 'E', 'ℱ': 'F', 'ℋ': 'H', 'ℑ': 'I', 'ℜ': 'R', 'ℨ': 'Z',
  // ═══ 科普特字母 ═══
  'ⲁ': 'a', 'ⲃ': 'b', 'ⲅ': 'r', 'ⲇ': 'd', 'ⲉ': 'e', 'ⲏ': 'h', 'ⲓ': 'i',
  'ⲕ': 'k', 'ⲙ': 'm', 'ⲛ': 'n', 'ⲟ': 'o', 'ⲣ': 'p', 'ⲥ': 'c', 'ⲧ': 't',
  'ⲩ': 'y', 'ⲭ': 'x', 'ⳏ': 'o',
  // ═══ 連字 ═══
  'ﬁ': 'fi', 'ﬂ': 'fl', 'ﬀ': 'ff', 'ﬃ': 'ffi', 'ﬄ': 'ffl', 'ﬅ': 'st',
  'ﬆ': 'st', 'Ǆ': 'DZ', 'ǅ': 'Dz', 'ǆ': 'dz', 'Ǉ': 'LJ', 'ǈ': 'Lj',
  'ǉ': 'lj', 'Ǌ': 'NJ', 'ǋ': 'Nj', 'ǌ': 'nj', 'ﬆ': 'st',
  // ═══ 常見詐騙用同形字 ═══
  'ɴ': 'n', 'ʟ': 'l', 'ғ': 'f', 'ᴎ': 'n', 'ᴧ': 'a', 'ꓥ': 'a', 'ꓦ': 'v',
  'ꓧ': 'h', 'ꓫ': 'x', 'ꓬ': 'y', 'ꓮ': 'e', 'ꓯ': 'v', 'ꓲ': 'i', 'ꓳ': 'o',
  'ꓴ': 'o', 'ꓵ': 'u', 'ꓷ': 'd', 'ꓸ': 'j', 'ꓹ': 'j', 'ꓺ': 'l', 'ꓻ': 'l',
  'ꓼ': 's', 'ꓽ': 's',
  // ═══ 零寬字元（直接移除）═══
  '\u200b': '', '\u200c': '', '\u200d': '', '\ufeff': '', '\u00ad': '',
  '\u2060': '', '\u180e': '', '\u2062': '', '\u2063': '', '\u2064': '',
};

function normalizeConfusables(str) {
  if (!str) return str;
  let result = '';
  for (const ch of str) {
    result += CONFUSABLE_MAP[ch] !== undefined ? CONFUSABLE_MAP[ch] : ch;
  }
  return result.toLowerCase();
}

// v2.3：簡體→繁體映射（常見詐騙用字，非完整映射）
const SIMPLIFIED_TO_TRADITIONAL = {
  '确': '確', '验': '驗', '证': '證', '银': '銀', '行': '行', '账': '帳',
  '户': '戶', '号': '號', '码': '碼', '输': '輸', '钱': '錢', '汇': '匯',
  '款': '款', '转': '轉', '单': '單', '订': '訂', '购': '購', '买': '買',
  '卖': '賣', '价': '價', '优': '優', '惠': '惠', '赚': '賺', '亏': '虧',
  '投': '投', '资': '資', '贷': '貸', '险': '險', '诈': '詐', '骗': '騙',
  '钓': '釣', '鱼': '魚', '链': '鏈', '结': '結', '冻': '凍', '锁': '鎖',
  '异': '異', '常': '常', '冲': '沖', '值': '值', '积': '積', '分': '分',
  '兑': '兌', '换': '換', '领': '領', '奖': '獎', '红': '紅', '包': '包',
  '限': '限', '时': '時', '仅': '僅', '剩': '剩', '抢': '搶', '拍': '拍',
  '运': '運', '费': '費', '现': '現', '金': '金', '佣': '傭', '提': '提',
  '个': '個', '讯': '訊', '联': '聯', '系': '繫', '客': '客', '服': '服',
  '登': '登', '录': '錄', '密': '密', '实': '實', '名': '名', '认': '認',
};

function simplifiedToTraditional(text) {
  if (!text) return text;
  let result = '';
  for (const ch of text) {
    result += SIMPLIFIED_TO_TRADITIONAL[ch] || ch;
  }
  return result;
}

// ════════════════════════════════════════
// 常數資料表
// ════════════════════════════════════════

const BRAND_DOMAINS = [
  { brand: '台灣銀行',   official: 'bot.com.tw',         asn: [] },
  { brand: '中國信託',   official: 'ctbcbank.com',        asn: [], aliases: ['ctbcsec.com'] },
  { brand: '玉山銀行',   official: 'esunbank.com.tw',     asn: [], aliases: ['esun-sec.com.tw'] },
  { brand: '國泰世華',   official: 'cathaybk.com.tw',     asn: [], aliases: ['cathaysec.com.tw'] },
  { brand: '富邦銀行',   official: 'fubon.com',           asn: [], aliases: ['fbs.com.tw','fubon.com.tw','fubonlife.com.tw'] },
  { brand: '台新銀行',   official: 'taishinbank.com.tw',  asn: [], aliases: ['tcsc.com.tw'] },
  { brand: '永豐銀行',   official: 'ubot.com.tw',         asn: [], aliases: ['sinopac.com','sinopac-sec.com.tw'] },
  { brand: '土地銀行',   official: 'landbank.com.tw',     asn: [] },
  { brand: '郵局',       official: 'post.gov.tw',         asn: [] },
  { brand: '元大',       official: 'yuanta.com.tw',       asn: [], aliases: ['yuantabank.com.tw','yuantafunds.com.tw','masterlink.com.tw'] },
  { brand: '凱基',       official: 'kgieworld.com.tw',    asn: [], aliases: ['kgi.com.tw'] },
  { brand: '兆豐',       official: 'megabank.com.tw',     asn: [], aliases: ['emega.com.tw','megasec.com.tw'] },
  { brand: '第一銀行',   official: 'firstbank.com.tw',    asn: [], aliases: ['ibf.com.tw'] },
  { brand: '華南銀行',   official: 'hncb.com.tw',         asn: [] },
  { brand: '群益',       official: 'capital.com.tw',      asn: [] },
  { brand: 'Google',     official: 'google.com',          asn: ['AS15169'] },
  { brand: 'Facebook',   official: 'facebook.com',        asn: ['AS32934'] },
  { brand: 'LINE',       official: 'line.me',             asn: [] },
  { brand: '蝦皮',       official: 'shopee.tw',           asn: [] },
  { brand: 'momo',       official: 'momo.com.tw',         asn: [], aliases: ['momoshop.com.tw'] },
  { brand: 'PChome',     official: 'pchome.com.tw',       asn: [], aliases: ['pcstore.com.tw'] },
  { brand: 'Apple',      official: 'apple.com',           asn: ['AS714'] },
  { brand: 'Microsoft',  official: 'microsoft.com',       asn: ['AS8075'] },
  { brand: '財政部',     official: 'mof.gov.tw',          asn: [] },
  { brand: '健保署',     official: 'nhi.gov.tw',          asn: [] },
];

// v2.3：合法金融機構白名單（銀行+券商+投信+期貨）
const LEGIT_FINANCIAL_DOMAINS = new Set([
  // 銀行
  'bot.com.tw','ctbcbank.com','esunbank.com.tw','cathaybk.com.tw',
  'fubon.com','taishinbank.com.tw','ubot.com.tw','landbank.com.tw',
  'post.gov.tw','megabank.com.tw','sinopac.com','firstbank.com.tw',
  'hncb.com.tw','taipeifubon.com.tw','entiebank.com.tw',
  'scsb.com.tw','tcb-bank.com.tw','bankchb.com','bos.com.tw',
  'skbank.com.tw','sunny-bank.com.tw','feib.com.tw','jihsunbank.com.tw',
  'ktb.com.tw','cotabank.com.tw','taiwancooperativebank.com.tw',
  // 證券/期貨/投信
  'fbs.com.tw','fubon.com.tw','fubonlife.com.tw',
  'kgieworld.com.tw','kgi.com.tw',
  'yuantabank.com.tw','yuanta.com.tw','yuantafunds.com.tw',
  'masterlink.com.tw','cathaysec.com.tw','jihsun.com.tw',
  'sinopac-sec.com.tw','sinotrade.com.tw',
  'emega.com.tw','megasec.com.tw','ibf.com.tw',
  'concords.com.tw','capital.com.tw','tcsc.com.tw',
  'esun-sec.com.tw','ctbcsec.com',
  'pfcf.com.tw','taifex.com.tw',
  // 國際券商/交易所
  'binance.com','coinbase.com','kraken.com',
  'etoro.com','interactivebrokers.com','schwab.com',
]);

const PARASITE_PLATFORMS = new Set([
  'notion.site','notion.so','github.io','web.app',
  'netlify.app','vercel.app','glitch.me','weebly.com',
  'wixsite.com','sites.google.com','forms.office.com',
  'sharepoint.com','blogspot.com','wordpress.com',
]);

const SENSITIVE_PATHS = [
  '/login', '/verify', '/bank/', '/secure/', '/api/auth',
  '/account/', '/confirm', '/payment', '/signin', '/update',
  '/validate', '/auth/', '/identity/', '/credential'
];

// v2.2：TLD 分級（取代舊的 RISKY_TLDS 陣列）
const TLD_TIER1_DIRECT_L4 = new Set(['.tk', '.ml', '.ga', '.cf', '.gq']);
const TLD_TIER2_STRONG = new Set(['.xyz', '.top', '.work', '.click', '.loan', '.shop', '.store', '.site', '.online', '.buzz', '.rest']);

// v2.2：ASN 分級（取代舊的國家分級）
const ASN_BULLETPROOF = new Set([
  // 已知 Bulletproof Hosting ASN（初始名單，需定期更新）
  'AS51659','AS58061','AS197695','AS202425','AS60781',
  'AS49349','AS206804','AS209160','AS44477','AS62904',
]);
const ASN_HIGH_ABUSE = new Set([
  // 歷史惡意比例 > 20% 的 ASN
  'AS14618','AS63949','AS18978','AS53667','AS20473',
  'AS46562','AS36352','AS26496','AS35916','AS46844',
]);
const ASN_LARGE_CLOUD = new Set([
  // 大型雲端 ASN（合法用途多，低基礎風險）
  'AS16509','AS14618',  // AWS
  'AS15169','AS396982',  // Google Cloud
  'AS8075',              // Microsoft Azure
  'AS13335',             // Cloudflare
  'AS45102',             // Alibaba Cloud
  'AS132203',            // Tencent Cloud
  'AS16276',             // OVH
  'AS24940',             // Hetzner
  'AS63949',             // Linode
  'AS20940',             // Akamai
]);

// v2.2：高濫用率註冊商（分級調整，Namecheap 降為弱負面因子）
const RISKY_REGISTRARS_L1 = ['freenom', 'west263', 'pdr ltd', 'publicdomainregistry'];
const RISKY_REGISTRARS_L2 = ['1&1', 'ionos', 'alibaba cloud', 'tucows', 'internet domain service'];
const RISKY_REGISTRARS_WEAK = ['namecheap'];  // v2.2：降級為弱負面，不再排除 T6

const SSO_WHITELIST = [
  'accounts.google.com', 'login.microsoftonline.com',
  'auth.line.me', 'appleid.apple.com', 'id.line.me',
  'www.facebook.com', 'api.twitter.com'
];

const FISHING_KEYWORDS = [
  'secure', 'login', 'verify', 'update', 'account',
  'confirm', 'banking', 'payment', 'signin', 'validate',
  'auth', 'wallet', 'invest', 'crypto', 'reward', 'prize'
];

// v2.2：TLD 去除正則（共用，避免遺漏 .me .us 等）
const TLD_STRIP_RE = /\.(com\.tw|org\.tw|net\.tw|gov\.tw|edu\.tw|com|tw|net|org|io|co|me|us|cc|tv|app|dev|xyz|top|site|shop|store|club|info|biz|mobi)$/;

// v2.2：語意分析詞庫（P0 用，擴充三類）
const SEMANTIC_KEYWORDS = {
  // 165 第一名：網路購物詐騙
  fake_shop:['貨到付款','限時特價','倒數','售完為止','免運費','數量有限','cash on delivery',
             '超低價','工廠直營','清倉','一折','下殺','秒殺','直購價','私下交易','面交匯款'],
  // 165 第二名：假投資詐騙
  invest:   ['入金','提幣','收益','vip','mt4','mt5','邀請碼','殺豬盤','加密交易所','invest','crypto','mining',
             '穩賺','日報酬','月配息','帶單','跟單','老師帶','投資群','保證獲利','翻倍','出金'],
  // 165 第三名：色情應召詐財
  escort:   ['約砲','約妹','外約','茶莊','魚訊','援交','車馬費','保證金','儲值點數','私密照',
             '定金','見面費','解鎖','成人','裸聊','視訊交友','包夜','全套'],
  // 165 第四名：假交友(投資詐財) — 殺豬盤
  romance:  ['我在投資','帶你賺','一起投資','我教你','交往','曖昧','想見你','加我私人',
             '我是單身','想認識你','你好可愛','緣分','命中注定','靈魂伴侶'],
  // 165 第五名：假買家騙賣家（取消分期/假退款）
  fake_buyer:['取消分期','交易異常','賣貨便','綠界','超商取貨','訂單問題','重新驗證',
              '客服確認','解除設定','分期扣款','連續扣款','誤設定','帳戶驗證','重複下單'],
  // 165 第六名：假求職詐騙
  job_scam: ['高薪','日領','在家賺','兼職','代理','手機即可','月入十萬','時薪破千',
             '徵才','招聘','保證金','制服費','金流測試','博弈','代操','打字員',
             '在家工作','輕鬆月入','高額獎金','免經驗','日入過萬','掛機賺'],
  // 165 第七名：虛擬遊戲詐騙
  game_scam:['代儲','代練','遊戲幣','虛寶','寶物交易','序號','點數卡','8591','先匯款再交易',
             '遊戲帳號','買賣帳號','便宜儲值','課金','鑽石','抽卡','保底'],
  // 假捐款/假公益
  charity_scam:['捐款','善款','募款','公益','弱勢','救助','震災','重建','愛心',
                '捐助','奉獻','慈善','急需','善心人士','幫助他們'],
  // 既有類別
  gov_fake: ['罰款','繳費','etc','台電','監理站','自來水','燃料費','違規','健保','勞保','國稅局'],
  lure:     ['恭喜','限時','中獎','免費','抽到','領取','點擊','congratulations','winner'],
  brush:    ['搶單','任務','傭金','洗碼量','提現','客服','在家工作','日領','時薪超高'],
  phishing: ['login','secure','verify','update','payment','bank','account','password'],
  refund:   ['退款','訂單異常','重新設定','帳號凍結','客服驗證','otp','簡訊驗證碼','refund','order error'],
  social:   ['加line','加whatsapp','私訊','約出來','視訊','加好友','add line','add whatsapp'],
};

const KNOWN_SAFE = new Set([
  // ── 政府機關（五院 + 各部會 + 獨立機關）──
  'gov.tw','edu.tw','moi.gov.tw','moea.gov.tw','mohw.gov.tw',
  'judicial.gov.tw','president.gov.tw','ly.gov.tw','fsc.gov.tw',
  'nhi.gov.tw','cdc.gov.tw','moe.gov.tw','motc.gov.tw',
  'twse.com.tw','tpex.org.tw','tdcc.com.tw','mof.gov.tw',
  'immigration.gov.tw','customs.gov.tw','boca.gov.tw',
  'npa.gov.tw','165.npa.gov.tw','tipo.gov.tw',
  // v3.0：補齊各部會
  'ey.gov.tw',              // 行政院
  'exam.gov.tw',            // 考試院
  'cy.gov.tw',              // 監察院
  'moda.gov.tw',            // 數位發展部
  'ndc.gov.tw',             // 國發會
  'dgpa.gov.tw',            // 人事行政總處
  'dgbas.gov.tw',           // 主計總處
  'mofa.gov.tw',            // 外交部
  'mnd.gov.tw',             // 國防部
  'moj.gov.tw',             // 法務部
  'mol.gov.tw',             // 勞動部
  'moa.gov.tw',             // 農業部
  'moenv.gov.tw',           // 環境部
  'ocac.gov.tw',            // 僑務委員會
  'hakka.gov.tw',           // 客委會
  'apc.gov.tw',             // 原住民族委員會
  'ncl.edu.tw',             // 國家圖書館
  'nat.gov.tw',             // 國家檔案管理局
  'cpa.gov.tw',             // 營建署
  'wda.gov.tw',             // 勞動力發展署
  'bli.gov.tw',             // 勞保局
  'lia.gov.tw',             // 勞動保險局
  'nta.gov.tw',             // 國稅局
  'etax.nat.gov.tw',        // 電子申報繳稅
  'einvoice.nat.gov.tw',    // 電子發票
  'data.gov.tw',            // 政府開放資料
  'gcis.nat.gov.tw',        // 商工登記
  'findbiz.nat.gov.tw',     // 商工查詢
  'tpb.gov.tw',             // 台灣菸酒
  'fia.gov.tw',             // 財政資訊中心
  'ncc.gov.tw',             // 通傳會
  'caa.gov.tw',             // 民航局
  'thb.gov.tw',             // 公路局
  'railway.gov.tw',         // 台鐵
  'metro.taipei',           // 台北捷運
  'health.gov.tw',          // 衛生福利部
  'cib.gov.tw',             // 刑事局
  'doh.gov.tw',             // 衛福部
  'taiwan.gov.tw',          // 我的E政府
  'e-land.gov.tw',          // 地政
  // ── 地方政府 ──
  'gov.taipei',             // 台北市政府
  'ntpc.gov.tw',            // 新北市
  'taoyuan.gov.tw',         // 桃園市
  'taichung.gov.tw',        // 台中市
  'tainan.gov.tw',          // 台南市
  'kcg.gov.tw',             // 高雄市
  // ── 公立醫院 ──
  'ntu.edu.tw','cgmh.org.tw','ntuh.gov.tw','vghtpe.gov.tw',
  'vghks.gov.tw',           // 高雄榮總
  'vghtc.gov.tw',           // 台中榮總
  'nckuh.org.tw',           // 成大醫院
  'kmuh.org.tw',            // 高醫
  'cmuh.cmu.edu.tw',        // 中國醫藥大學附設醫院
  // ── 財團法人 / 社團法人 / 公益團體 ──
  'twrf.org.tw',            // 台灣兒童暨家庭扶助基金會（家扶）
  'worldvision.org.tw',     // 台灣世界展望會
  'tifrr.org.tw',           // 創世基金會
  'eden.org.tw',            // 伊甸基金會
  'tzuchi.org.tw',          // 慈濟基金會
  'tzuchi.org',             // 慈濟（國際）
  'laf.org.tw',             // 法律扶助基金會
  'children.org.tw',        // 兒童福利聯盟
  'sunshine.org.tw',        // 陽光基金會
  'bhuntr.com',             // 畢嘉士基金會
  'redcross.org.tw',        // 中華民國紅十字會
  'sinica.edu.tw',          // 中研院
  'tfrd.org.tw',            // 罕病基金會
  'lohas.org.tw',           // 董氏基金會
  'syinlu.org.tw',          // 心路基金會
  'canlove.org.tw',         // 癌症希望基金會
  'tsmc-foundation.org',    // 台積電慈善基金會
  'hondao.org.tw',          // 弘道老人福利基金會
  'oldpeople.org.tw',       // 老人福利聯盟
  'togetherwecando.org.tw', // 聯合勸募
  'give416.org.tw',         // 捐血中心
  'blood.org.tw',           // 台灣血液基金會
  'humanrights.org.tw',     // 人權公約施行監督聯盟
  'greenpeace.org',         // 綠色和平
  'greenpeace.org.tw',      // 綠色和平台灣
  'tahr.org.tw',            // 台灣人權促進會
  'amnesty.tw',             // 國際特赦組織台灣
  'consumers.org.tw',       // 消費者文教基金會（消基會）
  'twnpos.org.tw',          // 台灣公益團體自律聯盟
  // ── 新聞媒體（補齊）──
  'udn.com','chinatimes.com','ltn.com.tw','ettoday.net',
  'tvbs.com.tw','pts.org.tw','cna.com.tw','storm.mg',
  'ithome.com.tw','inside.com.tw','bnext.com.tw','technews.tw',
  'setn.com','nownews.com','mirrormedia.mg',
  'ctitv.com.tw',           // 中天
  'ttv.com.tw',             // 台視
  'ftv.com.tw',             // 民視
  'ctv.com.tw',             // 中視
  'ebc.net.tw',             // 東森
  'nexttv.com.tw',          // 壹電視
  'mnews.tw',               // 鏡新聞
  'cw.com.tw',              // 天下雜誌
  'businesstoday.com.tw',   // 今周刊
  'gvm.com.tw',             // 遠見
  'wealth.com.tw',          // 財訊
  'commonhealth.com.tw',    // 康健
  'parenting.com.tw',       // 親子天下
  'thenewslens.com',        // 關鍵評論網
  'twreporter.org',         // 報導者
  'news.pts.org.tw',        // 公視新聞網
  'rti.org.tw',             // 中央廣播電台
  // ── 銀行 ──
  'bot.com.tw','landbank.com.tw','hncb.com.tw','firstbank.com.tw',
  'ctbcbank.com','esunbank.com.tw','taishinbank.com.tw',
  'megabank.com.tw','cathaybk.com.tw','fubon.com',
  'ubot.com.tw','sinopac.com','post.gov.tw','taiwanpost.com.tw',
  'scsb.com.tw','tcb-bank.com.tw','bankchb.com','bos.com.tw',
  'skbank.com.tw','sunny-bank.com.tw','feib.com.tw','jihsunbank.com.tw',
  'ktb.com.tw','cotabank.com.tw','taiwancooperativebank.com.tw',
  'entiebank.com.tw','taipeifubon.com.tw',
  // ── 證券/期貨/投信（v2.3 新增：解決 fbs.com.tw 等誤判）──
  'fbs.com.tw',           // 富邦證券
  'fubon.com.tw',         // 富邦金控
  'fubonlife.com.tw',     // 富邦人壽
  'kgieworld.com.tw',     // 凱基證券
  'kgi.com.tw',           // 凱基投信
  'yuantabank.com.tw',    // 元大銀行
  'yuanta.com.tw',        // 元大證券
  'yuantafunds.com.tw',   // 元大投信
  'masterlink.com.tw',    // 元富證券
  'cathaysec.com.tw',     // 國泰證券
  'jihsun.com.tw',        // 日盛證券
  'sinopac-sec.com.tw',   // 永豐金證券
  'sinotrade.com.tw',     // 統一證券
  'emega.com.tw',         // 兆豐證券
  'megasec.com.tw',       // 兆豐證券
  'ibf.com.tw',           // 第一金證券
  'concords.com.tw',      // 康和證券
  'capital.com.tw',       // 群益證券
  'tcsc.com.tw',          // 台新證券
  'esun-sec.com.tw',      // 玉山證券
  'ctbcsec.com',          // 中信證券
  'pfcf.com.tw',          // 元大期貨
  'taifex.com.tw',        // 台灣期交所
  // ── 電商/購物 ──
  'shopee.tw','momo.com.tw','pchome.com.tw','ruten.com.tw',
  'books.com.tw','momoshop.com.tw','pcstore.com.tw',
  'yahoo.com.tw','buy123.com.tw','rakuten.com.tw',
  // v3.0：合法開店/電商平台
  'shopline.tw','shopline.io','91app.com','ichef.tw','cyberbiz.co',
  'eslite.com','pinkoi.com','carrefour.com.tw','pxmart.com.tw',
  '7-11.com.tw','familymart.com.tw','costco.com.tw','ikea.com.tw',
  // v3.0：合法交易所
  'maicoin.com','max.maicoin.com','ace.io','bitopro.com',
  'binance.com','coinbase.com','kraken.com','okx.com',
  // v3.0：合法交友平台
  'pairs.lv','tinder.com','bumble.com',
  // v3.0：合法 SaaS/科技
  'notion.so','notion.site','vercel.app','railway.app',
  'figma.com','canva.com','slack.com','zoom.us','trello.com',
  // ── 房屋/租屋 ──
  '591.com.tw','sale.591.com.tw','rent.591.com.tw',
  'sinyi.com.tw','yungching.com.tw','rakuya.com.tw',
  'housefun.com.tw','cthouse.com.tw',
  // ── 財經資訊 ──
  'statementdog.com','goodinfo.tw','cnyes.com','moneydj.com',
  'cmoney.tw','histock.info','stockfeel.com.tw','cw.com.tw',
  'wantgoo.com','xq.com.tw','nvesto.com',
  // ── 新聞媒體 ──
  'udn.com','chinatimes.com','ltn.com.tw','ettoday.net',
  'tvbs.com.tw','pts.org.tw','cna.com.tw','storm.mg',
  'ithome.com.tw','inside.com.tw','bnext.com.tw','technews.tw',
  'setn.com','nownews.com','mirrorMedia.mg',
  // ── 電信 ──
  'chunghwa.com.tw','cht.com.tw','fetnet.net','taiwanmobile.com',
  'aptg.com.tw','fareastone.com.tw',
  // ── 社群/論壇 ──
  'ptt.cc','mobile01.com','dcard.tw','pixnet.net',
  'bahamut.com.tw','gamer.com.tw',  // 巴哈姆特
  // ── 票務/交通 ──
  'kktix.com','accupass.com','thsrc.com.tw','trtc.com.tw',
  // ── 求職 ──
  '104.com.tw','1111.com.tw','yes123.com.tw','cake.me',
  // ── 國際大站 ──
  'google.com','youtube.com','gmail.com','google.com.tw',
  'facebook.com','instagram.com','whatsapp.com',
  'microsoft.com','office.com','outlook.com','live.com',
  'apple.com','icloud.com','amazon.com','aws.amazon.com',
  'twitter.com','x.com','linkedin.com','tiktok.com',
  'netflix.com','spotify.com','wikipedia.org','github.com',
  'cloudflare.com','zoom.us','slack.com','notion.so',
  'paypal.com','stripe.com','visa.com','mastercard.com',
  'line.me','telegram.org','discord.com',
  'yahoo.com','bing.com','duckduckgo.com',
  'adobe.com','canva.com','wordpress.com','medium.com',
  'reddit.com','cnn.com','bbc.com','reuters.com',
  'nytimes.com','bloomberg.com','forbes.com',
  // ── 遊戲平台（合法）──
  'steam-powered.com','steampowered.com','store.steampowered.com',
  'epicgames.com','playstation.com','xbox.com','nintendo.com',
  'garena.com','garenatw.com',     // Garena 台灣
  'plaync.com.tw','beanfun.com',   // 遊戲橘子
  // ── 交友平台（合法）──
  'tinder.com','bumble.com','pairs.lv','match.com',
  // ── TrustInt ──
  'trustint.org','trustint.tw',
  // ── 國際金融科技（不該誤判）──
  'wise.com','revolut.com','transferwise.com',
  // ── 加密貨幣交易所（合法）──
  'binance.com','coinbase.com','kraken.com','bitfinex.com',
  // ── v3.0 GT 修正：FP 案例加入白名單 ──
  'nike.com','adidas.com','hm.com','zara.com',
  'uber.com','ubereats.com','foodpanda.com.tw',
  'airbnb.com','booking.com',
  'appier.com','91app.com','gogoro.com','kkbox.com',
  'ikea.com','muji.com','costco.com.tw','eslite.com',
  'familymart.com.tw','carrefour.com.tw','watsons.com.tw','pxmart.com.tw',
  'twitch.tv','uniqlo.com',
  // ── 汽車品牌 ──
  'bmw.com.tw','bmw.com','mercedes-benz.com.tw','mercedes-benz.com',
  'toyota.com.tw','toyota.com','honda.com.tw','honda.com',
  'lexus.com.tw','lexus.com','mazda.com.tw','mazda.com',
  'nissan.com.tw','nissan.com','ford.com.tw','ford.com',
  'audi.com.tw','audi.com','tesla.com','volvo.com.tw','volvo.com',
  'porsche.com.tw','porsche.com','volkswagen.com.tw','volkswagen.com',
  'hyundai.com.tw','hyundai.com','kia.com','subaru.com.tw','subaru.com',
  'mitsubishi-motors.com.tw','suzuki.com.tw','luxgen-motor.com.tw',
  // ── 台灣半導體/電子/科技（上市櫃）──
  'tsmc.com','tsmc.com.tw',           // 台積電
  'umc.com','umc.com.tw',             // 聯電
  'mediatek.com','mediatek.com.tw',   // 聯發科
  'asus.com','asus.com.tw',           // 華碩
  'acer.com','acer.com.tw',           // 宏碁
  'msi.com','msi.com.tw',             // 微星
  'gigabyte.com','gigabyte.com.tw',   // 技嘉
  'foxconn.com','honhai.com',         // 鴻海/富士康
  'pegatron.com',                     // 和碩
  'inventec.com',                     // 英業達
  'quanta.com.tw','quantatw.com',     // 廣達
  'compal.com',                       // 仁寶
  'wistron.com',                      // 緯創
  'realtek.com','realtek.com.tw',     // 瑞昱
  'novatek.com.tw',                   // 聯詠
  'himax.com.tw',                     // 奇景光電
  'aseglobal.com',                    // 日月光
  'spil.com.tw',                      // 矽品
  'nanya.com','nanyatechnology.com',  // 南亞科
  'winbond.com','winbond.com.tw',     // 華邦電
  'macronix.com',                     // 旺宏
  'powerchip.com',                    // 力積電
  'viseratech.com',                   // 采鈺
  'deltaelectronics.com','delta.com.tw','deltaww.com', // 台達電
  'liteon.com',                       // 光寶
  'advantech.com','advantech.com.tw',  // 研華
  'yageo.com',                        // 國巨
  'walsin.com',                       // 華新科
  'unimicron.com',                    // 欣興
  'zfranchise.com.tw',                // 臻鼎
  'catcher.com.tw',                   // 可成
  'largan.com.tw',                    // 大立光
  'silergy.com',                      // 矽力杰
  'aspeedtech.com',                   // 信驊
  'airtac.com',                       // 亞德客
  // ── 台灣傳產/製造/化工 ──
  'fpg.com.tw',                       // 台塑
  'fpcc.com.tw',                      // 台化
  'nfrpc.com.tw',                     // 南亞
  'fenc.com',                         // 遠東新
  'tcc.com.tw',                       // 台泥
  'acchl.com','asiacement.com',       // 亞泥
  'uni-president.com',                // 統一
  'foxconninterior.com',              // 鴻準
  'evergreen-marine.com','evergreen-marine.com.tw', // 長榮海運
  'yangming.com','yangming.com.tw',   // 陽明海運
  'wanhai.com','wanhai.com.tw',       // 萬海
  'hiwin.com.tw','hiwin.tw',          // 上銀
  'csc.com.tw',                       // 中鋼
  'hotaimotor.com.tw',                // 和泰車
  // ── 台灣金控/壽險 ──
  'cathayfhc.com.tw',                 // 國泰金
  'fubonlife.com.tw',                 // 富邦壽
  'sinopacholdings.com',              // 永豐金
  'ctbcholding.com',                  // 中信金
  'esunfhc.com',                      // 玉山金
  'megaholdings.com.tw',              // 兆豐金
  'taishinholdings.com.tw',           // 台新金
  'firstholding.com.tw',              // 第一金
  'hnfhc.com.tw',                     // 華南金
  'skfh.com.tw',                      // 新光金
  'mli.com.tw',                       // 新光人壽
  'cathaylife.com.tw',                // 國泰人壽
  'nanshanlife.com.tw',               // 南山人壽
  'pcalife.com.tw',                   // 保誠人壽
  'transglobe.com.tw',                // 全球人壽
  // ── 台灣電信/有線電視 ──
  'taiwanstar.com.tw',                // 台灣之星
  'gt.com.tw',                        // 亞太電信
  // ── 台灣食品/飲料/零售 ──
  'ttl.com.tw',                       // 台灣菸酒
  'wowprime.com',                     // 王品
  'uni-pres.com.tw',                  // 統一超商
  'hi-life.com.tw',                   // 萊爾富
  'okmart.com.tw',                    // OK 超商
  'rt-mart.com.tw',                   // 大潤發
  'poya.com.tw',                      // 寶雅
  'mia.com.tw',                       // 美廉社
  'nitori.com.tw',                    // 宜得利
  'cama.com.tw',                      // cama
  'louisa.coffee','louisacoffee.co',  // 路易莎
  'starbucks.com.tw',                 // 星巴克台灣
  'mcdonald.com.tw','mcdonalds.com',  // 麥當勞
  'kfc.com.tw',                       // 肯德基
  'mos.com.tw',                       // 摩斯
  'dominos.com.tw',                   // 達美樂
  'pizzahut.com.tw',                  // 必勝客
  // ── 台灣航空/旅遊 ──
  'evaair.com',                       // 長榮航空
  'china-airlines.com',               // 華航
  'mandarin-airlines.com',            // 華信航空
  'flytiger.com','tigerair.com',      // 虎航
  'starflyer.jp',                     // 星悅
  'eztravel.com.tw',                  // 易遊網
  'liontravel.com',                   // 雄獅
  'colatour.com.tw',                  // 可樂
  'settour.com.tw',                   // 東南旅遊
  'klook.com',                        // KLOOK
  'kkday.com',                        // KKday
  // ── 台灣物流/運輸 ──
  'kerryttc.com','sf-express.com',    // 嘉里大榮/順豐
  'pelican.delivery','tcat.com.tw',   // 黑貓
  // ── 台灣教育/醫療 ──
  'ntu.edu.tw','nthu.edu.tw','nctu.edu.tw','ncku.edu.tw',
  'nchu.edu.tw','ntust.edu.tw','ntnu.edu.tw','ccu.edu.tw',
  'cycu.edu.tw','fcu.edu.tw','tku.edu.tw','scu.edu.tw',
  'ntu.edu.tw','cgmh.org.tw','ntuh.gov.tw','vghtpe.gov.tw',
  'mmh.org.tw','chimei.org.tw','cmuh.cmu.edu.tw',
  // ── 國際科技巨頭 ──
  'google.com.hk','google.co.jp','android.com','chromium.org',
  'fb.com','meta.com','oculus.com',
  'azure.com','windows.com','xbox.com','msn.com',
  'icloud.com.cn','apple.com.tw',
  'oracle.com','ibm.com','intel.com','amd.com','nvidia.com',
  'qualcomm.com','broadcom.com','cisco.com','vmware.com',
  'salesforce.com','servicenow.com','workday.com','snowflake.com',
  'palantir.com','databricks.com','confluent.io',
  'samsung.com','lg.com','sony.com','panasonic.com','toshiba.com',
  'dell.com','hp.com','lenovo.com',
  'huawei.com','xiaomi.com','oppo.com','vivo.com',
  'dropbox.com','box.com','evernote.com','trello.com',
  'atlassian.com','jira.com','bitbucket.org','gitlab.com',
  'twilio.com','sendgrid.com','mailchimp.com',
  'shopify.com','squarespace.com','wix.com',
  'figma.com','sketch.com','invisionapp.com',
  'openai.com','anthropic.com','stability.ai','midjourney.com',
  // ── 國際金融 ──
  'jpmorgan.com','goldmansachs.com','morganstanley.com',
  'citi.com','citibank.com','hsbc.com','barclays.com',
  'bankofamerica.com','wellsfargo.com','ubs.com','db.com',
  'americanexpress.com','amex.com',
  'schwab.com','fidelity.com','vanguard.com','etrade.com',
  'robinhood.com','interactivebrokers.com','etoro.com',
  // ── 國際電商/零售 ──
  'amazon.co.jp','amazon.de','amazon.co.uk',
  'ebay.com','etsy.com','walmart.com','target.com',
  'bestbuy.com','homedepot.com','lowes.com',
  'alibaba.com','aliexpress.com','taobao.com','jd.com',
  'rakuten.co.jp','mercari.com',
  // ── 國際服飾/精品 ──
  'gucci.com','louisvuitton.com','lvmh.com','hermes.com',
  'chanel.com','prada.com','dior.com','burberry.com',
  'coach.com','michaelkors.com','ralphlauren.com','gap.com',
  'lululemon.com','newbalance.com','puma.com','underarmour.com',
  'skechers.com','asics.com','converse.com',
  // ── 國際食品/飲料 ──
  'coca-cola.com','pepsi.com','nestle.com','danone.com',
  'mcdonalds.com','starbucks.com','subway.com',
  'pg.com','unilever.com','loreal.com',
  // ── 國際旅遊/航空 ──
  'expedia.com','tripadvisor.com','hotels.com','agoda.com',
  'trip.com','skyscanner.com','kayak.com',
  'united.com','aa.com','delta.com','southwest.com',
  'emirates.com','cathaypacific.com','singaporeair.com',
  'ana.co.jp','jal.com',
  // ── 國際娛樂/串流 ──
  'disneyplus.com','disney.com','hbomax.com','hulu.com',
  'primevideo.com','twitch.tv','crunchyroll.com',
  'apple.tv','music.apple.com',
  // ── 國際新聞/媒體 ──
  'wsj.com','ft.com','economist.com','washingtonpost.com',
  'bbc.co.uk','theguardian.com','aljazeera.com',
  'apnews.com','afp.com','kyodonews.jp','nhk.or.jp',
  // ── 大站子域名（不應被寄生平台規則誤判）──
  'sites.google.com','docs.google.com','drive.google.com','forms.gle',
  'forms.office.com','sharepoint.com',
]);

// ════════════════════════════════════════
// 輔助檢查函式
// ════════════════════════════════════════

function isParasitePlatform(domain) {
  // 根域名本身不算寄生（如 notion.so），只有子域名才算（如 xxx.notion.site）
  for (const p of PARASITE_PLATFORMS) {
    if (domain.endsWith('.' + p)) return true;
    // 平台根域名本身：只在不在白名單時才視為寄生
    if (domain === p && !KNOWN_SAFE.has(domain)) return true;
  }
  return false;
}

// v2.2 修正：Leet-speak 正規化
// 有些字元有多種對應（1→l 或 i），所以產生多個變體
function normalizeLeetVariants(str) {
  const base = str.replace(/0/g, 'o').replace(/3/g, 'e')
                  .replace(/5/g, 's').replace(/\$/g, 's').replace(/@/g, 'a')
                  .replace(/4/g, 'a').replace(/7/g, 't');
  // 1 可能是 l 或 i，產生兩個變體
  const variant1 = base.replace(/1/g, 'l');
  const variant2 = base.replace(/1/g, 'i');
  const variants = new Set([variant1, variant2]);
  // 如果原始字串沒有 1，兩個變體相同，Set 會自動去重
  return [...variants];
}

function isBrandSpoof(clean, cleanBase) {
  const decoded = decodePunycode(clean);
  
  // v2.3.1：先做 Confusable 正規化（ATK-3 防禦）
  const confusableNormalized = normalizeConfusables(cleanBase);
  const decodedConfusable = normalizeConfusables(decoded.replace(TLD_STRIP_RE, ''));
  
  // Leet-speak 正規化（在 Confusable 正規化後再做）
  const normalizedVariants = normalizeLeetVariants(confusableNormalized);

  for (const b of BRAND_DOMAINS) {
    const officialBase = b.official.replace(TLD_STRIP_RE, '').toLowerCase();

    // 排除：查詢的就是官方域名本身或其子域名
    if (clean === b.official || clean.endsWith('.' + b.official)) continue;
    // 排除：品牌的別名域名（如 fbs.com.tw 是 fubon.com 的合法子公司）
    if (b.aliases && b.aliases.some(a => clean === a || clean.endsWith('.' + a))) continue;
    // 排除：查詢域名在白名單中
    if (KNOWN_SAFE.has(clean)) continue;
    // 排除：查詢域名是白名單域名的子域名
    if (Array.from(KNOWN_SAFE).some(s => clean.endsWith('.' + s))) continue;
    // 排除：品牌官方的子產品域名（如 google-analytics.com 是 Google 官方產品）
    const BRAND_PRODUCT_DOMAINS = [
      'google-analytics.com','googleadservices.com','googleapis.com',
      'googlesyndication.com','googletagmanager.com','googleusercontent.com',
      'gstatic.com','doubleclick.net',
      'facebook.net','fbcdn.net','fbsbx.com',
      'apple-dns.net','apple.news','mzstatic.com',
      'microsoftonline.com','microsoftedge.com','azure.com',
    ];
    if (BRAND_PRODUCT_DOMAINS.some(d => clean === d || clean.endsWith('.' + d))) continue;

    const decodedBase = decoded.replace(TLD_STRIP_RE, '').toLowerCase();

    // v3.0 安全修正：短名稱保護
    // officialBase 長度 ≤ 3（如 bot、kfc、ibm）時，Levenshtein ≤ 2 會誤判大量無辜域名
    // 改為只允許距離 ≤ 1，或直接跳過 Levenshtein 只用精確比對
    const maxDist = officialBase.length <= 3 ? 0 : (officialBase.length <= 5 ? 1 : 2);

    // v2.3.1：先用 Confusable 正規化後的版本比對（ATK-3 防禦）
    if (levenshtein(confusableNormalized, officialBase) <= maxDist ||
        levenshtein(decodedConfusable, officialBase) <= maxDist) {
      return b;
    }

    // Levenshtein 距離檢查（原始 + Punycode 解碼）
    if (levenshtein(cleanBase.toLowerCase(), officialBase) <= maxDist ||
        levenshtein(decodedBase, officialBase) <= maxDist) {
      return b;
    }

    // v2.3.1：Jaro-Winkler 相似度檢查（含 Confusable 正規化）
    // v3.0：短名稱提高閾值到 0.95（3 字元的 JW 很容易高分）
    const jwThreshold = officialBase.length <= 3 ? 0.95 : 0.88;
    if (jaroWinkler(confusableNormalized, officialBase) >= jwThreshold ||
        jaroWinkler(decodedConfusable, officialBase) >= jwThreshold ||
        jaroWinkler(cleanBase.toLowerCase(), officialBase) >= jwThreshold ||
        jaroWinkler(decodedBase, officialBase) >= jwThreshold) {
      return b;
    }

    // Leet-speak 正規化後再做 Levenshtein（所有變體）
    for (const variant of normalizedVariants) {
      if (variant !== confusableNormalized && levenshtein(variant, officialBase) <= 2) {
        return b;
      }
    }

    // 子字串包含品牌名（僅限 officialBase 長度 ≥ 4，避免短名稱誤判）
    if (officialBase.length >= 4) {
      if (confusableNormalized.includes(officialBase)) return b;
      if (cleanBase.toLowerCase().includes(officialBase)) return b;
      for (const variant of normalizedVariants) {
        if (variant.includes(officialBase)) return b;
      }
    }

    // 品牌中文名檢查
    if (b.brand.length >= 2 && cleanBase.includes(b.brand.toLowerCase())) {
      return b;
    }
  }
  return null;
}

function mkResult(level, label, should_block, code, desc, isMajestic = false) {
  const colors = { 1:'#166534', 2:'#1D4ED8', 3:'#92400E', 4:'#C05621', 5:'#991B1B' };
  return { level, label, label_color: colors[level], should_block,
    is_majestic: isMajestic, reasons: [{ code, desc }] };
}

// v2.2：ASN 風險分級函式（取代國家分級）
function classifyASN(asString) {
  if (!asString) return 'neutral';
  const asn = asString.split(' ')[0]; // "AS15169 Google LLC" → "AS15169"
  if (ASN_BULLETPROOF.has(asn)) return 'bulletproof';
  if (ASN_HIGH_ABUSE.has(asn))  return 'high_abuse';
  if (ASN_LARGE_CLOUD.has(asn)) return 'large_cloud';
  return 'neutral';
}

// v2.2：語意分析（計算各類命中數，回傳命中類別與 risk 加權）
function analyzeSemantics(text) {
  if (!text) return { categories: [], riskAdd: 0, crossCategory: false };
  // v2.3：先做簡體→繁體轉換，再做比對
  const lower = simplifiedToTraditional(text).toLowerCase();
  const hit = [];
  for (const [cat, keywords] of Object.entries(SEMANTIC_KEYWORDS)) {
    const count = keywords.filter(k => lower.includes(k)).length;
    if (count >= 1) hit.push({ cat, count });
  }
  const categories = hit.map(h => h.cat);
  const sameClassHigh = hit.some(h => h.count >= 2);
  const crossCategory = categories.length >= 2;
  let riskAdd = 0;
  if (sameClassHigh) riskAdd += 0.2;
  if (crossCategory) riskAdd += 0.3;
  return { categories, riskAdd, crossCategory, sameClassHigh };
}

// v2.2：偵測是否為一頁式結構（CC19 用）
function isOnePageStructure(urlscanData) {
  if (!urlscanData) return false;
  const pageDomain = urlscanData.page?.domain || '';
  // 白名單網域不做一頁式偵測（避免 google.com 等大站誤判）
  if (KNOWN_SAFE.has(pageDomain) ||
      Array.from(KNOWN_SAFE).some(s => pageDomain.endsWith('.' + s))) {
    return false;
  }
  const links = urlscanData.lists?.urls || [];
  const uniqueInternalPaths = new Set();
  for (const u of links) {
    try {
      const parsed = new URL(u);
      if (parsed.hostname === pageDomain || parsed.hostname.endsWith('.' + pageDomain)) {
        uniqueInternalPaths.add(parsed.pathname);
      }
    } catch {}
  }
  // 一頁式判斷：內部路徑 ≤ 3（首頁+1~2個資源路徑）
  return uniqueInternalPaths.size <= 3;
}

// ════════════════════════════════════════
// P1：快速判斷（/v1/check 使用）
// ════════════════════════════════════════
function getLevel(gsbHit, domain, urlPath = '') {
  const clean = domain.toLowerCase().replace(/^www\./, '');
  const cleanBase = clean.replace(TLD_STRIP_RE, '');

  // v3.0 修正：白名單平台根域名豁免（sites.google.com 等）
  // 這些大站的根域名可能被 GSB 標記（因為寄生內容），但根域名本身是安全的
  const isKnownSafe = KNOWN_SAFE.has(clean) ||
    Array.from(KNOWN_SAFE).some(s => clean.endsWith('.' + s));
  const isParasite = isParasitePlatform(clean);
  if (isKnownSafe && !isParasite)
    return mkResult(2, '安心信任', false, 'WHITELIST', '已知安全網域');

  // A群：Hard Rules（直接 L5）
  if (gsbHit)
    return mkResult(5, '多項安全指標異常', true, 'GSB', '命中 Google Safe Browsing');
  if (openPhishList.has(clean))
    return mkResult(5, '多項安全指標異常', true, 'OPENPHISH', '命中 OpenPhish 釣魚資料庫');
  if (npaBlacklist.has(clean))
    return mkResult(5, '多項安全指標異常', true, 'NPA165', '命中 165 反詐騙黑名單');

  // B1：品牌仿冒（單獨 L4）
  const spoofResult = isBrandSpoof(clean, cleanBase);
  if (spoofResult)
    return mkResult(4, '極高風險', true, 'BRAND_SPOOF', `疑似仿冒 ${spoofResult.brand} 官方網域`);

  // TLD Tier 1：直接 L4
  const tld = '.' + clean.split('.').pop();
  if (TLD_TIER1_DIRECT_L4.has(tld))
    return mkResult(4, '極高風險', true, 'TLD_TIER1', `使用免費高濫用 TLD（${tld}），直接高風險`);

  // v3.0：TLD Tier 2 + 不在 Majestic/KNOWN_SAFE → L4
  // .shop/.site/.top/.xyz/.work/.click/.loan/.store 這些 TLD 的合法站很少
  // 如果一個站用這些 TLD 又不在任何信譽資料庫裡，幾乎可以確定有問題
  if (TLD_TIER2_STRONG.has(tld) && !isKnownSafe && !majesticList.has(clean))
    return mkResult(4, '極高風險', true, 'TLD_TIER2_UNKNOWN', `使用高濫用率 TLD（${tld}）且非已知網站`);

  // v3.0：仿冒政府域名模式偵測（品牌-gov-tw.com / 品牌-gov.tw.net 等）
  if (/[-.]gov[-.]?tw/i.test(clean) && !clean.endsWith('.gov.tw') && !isKnownSafe)
    return mkResult(4, '極高風險', true, 'FAKE_GOV_DOMAIN', '域名含 gov-tw 但非 .gov.tw 官方域名，疑似仿冒政府網站');

  // v3.0：仿冒品牌+退款/驗證模式（brand-refund/verify/security.xxx）
  const suspiciousPatterns = ['refund', 'verify', 'security-check', 'confirm', 'update-info', 'giveaway', 'reward', 'survey-reward'];
  if (suspiciousPatterns.some(p => clean.includes(p)) && !isKnownSafe && !majesticList.has(clean))
    return mkResult(4, '極高風險', true, 'SUSPICIOUS_PATTERN', '域名含可疑關鍵字（退款/驗證/獎品），疑似詐騙');

  // 敏感路徑
  if (urlPath) {
    const hasSensitivePath = SENSITIVE_PATHS.some(p => urlPath.toLowerCase().includes(p));
    if (hasSensitivePath && !isKnownSafe)
      return mkResult(4, '極高風險', true, 'SENSITIVE_PATH', `URL 含敏感路徑：${urlPath}`);
  }

  // Punycode 弱訊號
  if (clean.includes('xn--'))
    return mkResult(3, '未知網域', false, 'PUNYCODE', '網域含國際化字元（同形異義字風險）');

  const isMajestic = majesticList.has(clean);
  return mkResult(3, '未知網域', false, 'NO_DATA', '此網域尚未被驗證，請自行判斷', isMajestic);
}

// ════════════════════════════════════════
// P5：分群機率模型（v2.2 重構）
// ════════════════════════════════════════
function calcSoftRisk(factors) {
  const {
    domainAgeDays, whoisHidden, privacyProtection, isHighAbuseRegistrar,
    asnTier, vtMalicious, abuseScore,
    hasFishingKeyword, hasMultiSubdomain, isDGA,
    registrar, tld,
    certAgeDays, hasHttps, certType,
    reputationInconsistency,
    // v2.2 新增行為特徵
    isOnePage, hasClipboardAPI, hasSocialLure, hasAdTraffic,
    pathEntropy, pathLength, urlLength,
    // v2.3 新增信譽評分
    ipqsScore, ipqsPhishing, ipqsMalware, apiFailCount
  } = factors;

  // ── 群1：網域年齡 ──
  let r1 = 0;
  if (domainAgeDays !== null) {
    if (domainAgeDays < 14)       r1 = 0.45;
    else if (domainAgeDays < 30)  r1 = 0.35;
    else if (domainAgeDays < 90)  r1 = 0.25;
    else if (domainAgeDays < 180) r1 = 0.12;
    else if (domainAgeDays < 365) r1 = 0.06;
  }

  // ── 群2：WHOIS 透明度（v2.2 重構）──
  let r2 = 0;
  if (whoisHidden && privacyProtection && isHighAbuseRegistrar) {
    r2 = 0.28;  // 完全隱藏 + 高濫用註冊商
  } else if (whoisHidden && privacyProtection) {
    r2 = 0.18;  // v2.2：一般註冊商從 0.28 降至 0.18
  } else if (whoisHidden || privacyProtection) {
    r2 = 0.10;  // v2.2：從 0.15 降至 0.10
  }
  // v2.2：Namecheap 弱負面因子
  if (registrar) {
    const regLower = registrar.toLowerCase();
    if (RISKY_REGISTRARS_WEAK.some(r => regLower.includes(r))) {
      r2 = Math.max(r2, r2 + 0.05);
    }
  }

  // ── 群3：IP/ASN 風險（v2.2：改為 ASN 層級判斷）──
  let r3 = 0;
  switch (asnTier) {
    case 'bulletproof':  r3 = 0.45; break;   // Tier 1
    case 'high_abuse':   r3 = 0.30; break;   // Tier 2
    case 'large_cloud':  r3 = 0.08; break;   // Tier 3（v2.2：雲端不直接高風險）
    case 'safe':         r3 = -0.08; break;  // Tier 4
    default:             r3 = 0; break;      // neutral
  }

  // ── 群4：憑證風險 ──
  let r4 = 0;
  if (!hasHttps) {
    r4 = 0.45;
  } else if (certType === 'DV' && certAgeDays !== null && certAgeDays < 30) {
    r4 = 0.25;
  } else if (certType === 'DV') {
    r4 = 0.08;
  } else if (certType === 'OV' || certType === 'EV') {
    r4 = -0.12;
  }

  // ── 群5：信譽評分（v2.3：加入 IPQS 分數）──
  let r5 = 0;
  
  // VT + AbuseIPDB（原有）
  if (vtMalicious >= 5)                              r5 = 0.40;
  else if (vtMalicious >= 3)                         r5 = 0.30;
  else if (abuseScore >= 75)                         r5 = 0.38;
  else if (abuseScore >= 50)                         r5 = 0.25;
  else if (vtMalicious >= 1)                         r5 = 0.18;
  else if (abuseScore >= 30)                         r5 = 0.12;
  else if (vtMalicious === 0 && abuseScore === 0)    r5 = -0.15;
  
  // IPQS 加成（v2.3 新增：讓 IPQS 有持續性影響）
  if (ipqsPhishing || ipqsMalware)                   r5 = Math.max(r5, 0.45);
  else if (ipqsScore >= 90)                          r5 = Math.max(r5, 0.40);
  else if (ipqsScore >= 75)                          r5 = Math.max(r5, 0.30);
  else if (ipqsScore >= 60)                          r5 = Math.max(r5, 0.18);
  
  // 多 API 同時失敗懲罰（v2.3：資料不足 = 風險未知，不該降低風險）
  if (apiFailCount >= 3) r5 = Math.max(r5, 0.15);
  else if (apiFailCount >= 2) r5 = Math.max(r5, 0.08);

  // v2.3.1 新增（ATK-6 防禦）：新站（< 30 天）不給信譽加分
  // 「全安全」對新站不代表真的安全，只代表還沒被掃到
  if (domainAgeDays !== null && domainAgeDays < 30 && r5 < 0) {
    r5 = 0;  // 新網域的負值（信任加分）不生效，改為中性
  }

  // ── 群6：行為特徵（v2.2 擴充）──
  let r6 = 0;
  if (isDGA)                                         r6 = Math.max(r6, 0.30);
  if (hasFishingKeyword && hasMultiSubdomain)         r6 = Math.max(r6, 0.25);
  if (hasClipboardAPI)                                r6 = Math.max(r6, 0.25);  // v2.2 新增
  if (isOnePage)                                      r6 = Math.max(r6, 0.22);  // v2.2 新增
  if (hasAdTraffic)                                   r6 = Math.max(r6, 0.20);
  if (hasMultiSubdomain && hasFishingKeyword)         r6 = Math.max(r6, 0.18);
  if (hasSocialLure)                                  r6 = Math.max(r6, 0.15);  // v2.2 新增
  if (pathEntropy > 3.5 && pathLength >= 8)           r6 = Math.max(r6, 0.15);
  if (hasFishingKeyword)                              r6 = Math.max(r6, 0.08);
  if (urlLength > 100)                                r6 = Math.max(r6, 0.08);

  // TLD Tier 2 強因子
  if (tld && TLD_TIER2_STRONG.has(tld)) {
    r6 += 0.20;  // v2.3：改為累加（不再 Math.max），與廣告導流疊加
  }
  // v2.3：r6 上限 cap 0.60（防止過度膨脹）
  r6 = Math.min(r6, 0.60);

  // 高濫用率註冊商加權
  if (registrar) {
    const regLower = registrar.toLowerCase();
    if (RISKY_REGISTRARS_L1.some(r => regLower.includes(r))) r6 = Math.max(r6, 0.15);
    else if (RISKY_REGISTRARS_L2.some(r => regLower.includes(r))) r6 = Math.max(r6, 0.08);
  }

  // 信譽不一致稀釋
  if (reputationInconsistency) r1 = r1 * 0.3;

  // ── 跨群加乘（Cross-Group Multiplier）── v2.3：全部加上明確上限
  // 極新網域 × 憑證風險
  if (domainAgeDays !== null && domainAgeDays < 14 && r4 > 0)
    r4 = Math.min(r4 * 1.5, 0.90);
  // WHOIS 完全隱藏 + 高風險 ASN
  if (r2 >= 0.18 && r3 >= 0.22)
    r3 = Math.min(r3 * 1.3, 0.85);  // v2.3：上限從 0.90 降至 0.85
  // 釣魚關鍵字 × 新網域
  if (hasFishingKeyword && (domainAgeDays === null || domainAgeDays < 30))
    r6 = Math.min(r6 * 1.4, 0.85);
  // 廣告 × 新網域（v2.3：domainAgeDays null 也觸發，年齡不明 = 可疑）
  if (hasAdTraffic && (domainAgeDays === null || domainAgeDays < 90))
    r6 = Math.min(r6 * 1.5, 0.88);
  // entropy domain × entropy path 同時高
  if (isDGA && pathEntropy > 3.5)
    r6 = Math.min(r6 * 1.4, 0.85);
  // v2.2 新增：一頁式 × 廣告 × 新網域
  if (isOnePage && hasAdTraffic && (domainAgeDays === null || domainAgeDays < 30))
    r6 = Math.min(r6 * 1.6, 0.92);

  // ── v2.3：相關性修正（無惡意信號衰減）──
  const hasNoMaliciousSignal = r5 <= 0 && r6 <= 0;
  let adj_r1 = r1, adj_r2 = r2, adj_r3 = r3, adj_r4 = r4;
  if (hasNoMaliciousSignal) {
    adj_r1 = r1 * 0.6;
    adj_r2 = r2 * 0.6;
    adj_r3 = r3 * 0.6;
    adj_r4 = r4 * 0.6;
  }

  // ── v3.0：負向信號（信任減分）——降低合法老站誤判 ──
  let trustBonus = 0;
  // 域名年齡 > 5 年
  if (domainAgeDays && domainAgeDays > 1825) trustBonus += 0.10;
  // 域名年齡 > 2 年
  else if (domainAgeDays && domainAgeDays > 730) trustBonus += 0.05;
  // 爬蟲偵測到完整法律頁面（隱私政策 + 服務條款）
  if (factors.hasLegalPages) trustBonus += 0.08;
  // 爬蟲偵測到公司資訊（公司名 + 電話或地址）
  if (factors.hasCompanyInfo) trustBonus += 0.10;
  // OV/EV 憑證（已在 r4 處理，此處額外加分）
  if (certType === 'OV' || certType === 'EV') trustBonus += 0.05;
  // 上限：信任減分最多 0.25
  trustBonus = Math.min(trustBonus, 0.25);

  // ── 聯集公式：Risk = 1 - Π(1 - risk_i) ──
  let risk = 1 - [adj_r1, adj_r2, adj_r3, adj_r4, r5, r6]
    .reduce((prod, r) => prod * (1 - r), 1);

  // v3.0：套用信任減分
  risk = risk - trustBonus;

  // v2.3：最終值 clamp 到 [0, 1]
  risk = Math.min(Math.max(risk, 0), 1);

  // v2.3：新站保護上限（V2-AI 動態閾值）
  if (hasNoMaliciousSignal && r3 <= 0.08) {
    risk = Math.min(risk, ENGINE_THRESHOLDS.new_site_cap);
  }

  return { risk, r1, r2, r3, r4, r5, r6 };
}

// ════════════════════════════════════════
// P6：Safe Scoring（v2.2 調整）
// ════════════════════════════════════════
function checkSafeScoring(factors, softRisk) {
  const { domainAgeDays, vtMalicious, abuseScore, asnTier, registrar,
          hasCriticalSignal, hasCriticalCluster, hasBHR } = factors;

  // P1-01：資料不足不升 L2（Fail-Cautious）
  if (factors.apiFailCount >= 2) return false;

  // 保護機制：有任何嚴重命中不可升 L2
  if (hasCriticalSignal || hasCriticalCluster || hasBHR) return false;
  // H1：網域 > 180 天
  if (!domainAgeDays || domainAgeDays < 180) return false;
  // H5：Soft Risk < safe_risk_cap（V2-AI 動態閾值）
  if (softRisk >= ENGINE_THRESHOLDS.safe_risk_cap) return false;

  // 信任指標（至少 2 項）
  let trustScore = 0;
  // T1：網域 > 2 年
  if (domainAgeDays > 730) trustScore++;
  // T2：ASN 低風險（v2.2：改為 ASN 層級）
  if (asnTier === 'safe' || asnTier === 'large_cloud') trustScore++;
  // T3：WHOIS 可追蹤（由 factors.whoisVisible 判斷）
  if (factors.whoisVisible) trustScore++;
  // T4：VirusTotal 全安全
  if (vtMalicious === 0) trustScore++;
  // T5：AbuseIPDB 無紀錄
  if (abuseScore === 0) trustScore++;
  // T6：非高濫用率註冊商（v2.2：Namecheap 不再排除）
  if (registrar) {
    const regLower = registrar.toLowerCase();
    const isRisky = RISKY_REGISTRARS_L1.some(r => regLower.includes(r)) ||
                    RISKY_REGISTRARS_L2.some(r => regLower.includes(r));
    if (!isRisky) trustScore++;
  }

  return trustScore >= 2;
}

// ══════════════════════════════════════════════════════════════════════
// V2-AI：自適應閾值校正框架
// 用 FP/FN 回報 + GT 結果回饋來微調 P5 閾值和權重
// ══════════════════════════════════════════════════════════════════════

// 可調閾值（預設值 = 目前手調結果）
const ENGINE_THRESHOLDS = {
  // Risk → Level 映射閾值
  risk_l4: 0.80,      // risk >= 此值 → L4
  risk_l3_high: 0.50,  // risk >= 此值 → L3（偏高風險）
  risk_l3: 0.20,       // risk >= 此值 → L3（未知）
  safe_risk_cap: 0.25, // P6 SafeScoring 的 risk 上限

  // P5 群權重乘數（1.0 = 不調整）
  w_age: 1.0,          // 群1：網域年齡
  w_whois: 1.0,        // 群2：WHOIS 透明度
  w_asn: 1.0,          // 群3：IP/ASN 風險
  w_cert: 1.0,         // 群4：憑證風險
  w_reputation: 1.0,   // 群5：信譽評分
  w_behavior: 1.0,     // 群6：行為特徵

  // 新站保護上限
  new_site_cap: 0.45,

  // 校正元數據
  calibration_version: 0,
  last_calibrated: null,
};

// 從 DB 載入已儲存的閾值（啟動時）
async function loadThresholds() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS engine_thresholds (
        id INT PRIMARY KEY DEFAULT 1,
        thresholds JSONB NOT NULL,
        calibration_log JSONB DEFAULT '[]',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    const result = await pool.query('SELECT thresholds FROM engine_thresholds WHERE id = 1');
    if (result.rows.length > 0) {
      const saved = result.rows[0].thresholds;
      Object.assign(ENGINE_THRESHOLDS, saved);
      console.log(`[V2-AI] 閾值載入成功（校正版本 ${ENGINE_THRESHOLDS.calibration_version}）`);
    } else {
      // 初始化
      await pool.query(
        'INSERT INTO engine_thresholds (id, thresholds) VALUES (1, $1)',
        [JSON.stringify(ENGINE_THRESHOLDS)]
      );
      console.log('[V2-AI] 閾值初始化完成');
    }
  } catch (err) {
    console.log('[V2-AI] 閾值載入失敗（使用預設值）：', err.message);
  }
}
setTimeout(loadThresholds, 5000);

// 儲存閾值到 DB
async function saveThresholds(reason) {
  try {
    ENGINE_THRESHOLDS.last_calibrated = new Date().toISOString();
    ENGINE_THRESHOLDS.calibration_version++;
    await pool.query(
      `UPDATE engine_thresholds SET thresholds = $1, updated_at = NOW() WHERE id = 1`,
      [JSON.stringify(ENGINE_THRESHOLDS)]
    );
    // 記錄校正日誌
    await pool.query(
      `UPDATE engine_thresholds SET calibration_log = calibration_log || $1::jsonb WHERE id = 1`,
      [JSON.stringify([{ version: ENGINE_THRESHOLDS.calibration_version, reason, timestamp: new Date().toISOString() }])]
    );
    console.log(`[V2-AI] 閾值儲存成功（v${ENGINE_THRESHOLDS.calibration_version}，原因：${reason}）`);
  } catch (err) {
    console.error('[V2-AI] 閾值儲存失敗：', err.message);
  }
}

// FP/FN 累積計數器（每日校正用）
const calibrationBuffer = {
  fp_count: 0,       // 合法被判危險
  fn_count: 0,       // 詐騙被判安全
  fp_domains: [],    // FP 域名列表（最多保留 50 筆）
  fn_domains: [],    // FN 域名列表
  total_checks: 0,
  last_reset: new Date().toISOString().split('T')[0],
};

// 記錄 FP/FN（由 /v1/report 呼叫）
function recordCalibrationSignal(domain, reportType, currentLevel) {
  if (reportType === 'false_positive' && currentLevel >= 4) {
    calibrationBuffer.fp_count++;
    if (calibrationBuffer.fp_domains.length < 50) {
      calibrationBuffer.fp_domains.push({ domain, level: currentLevel, time: Date.now() });
    }
  } else if (reportType === 'false_negative' && currentLevel <= 3) {
    calibrationBuffer.fn_count++;
    if (calibrationBuffer.fn_domains.length < 50) {
      calibrationBuffer.fn_domains.push({ domain, level: currentLevel, time: Date.now() });
    }
  }
}

// 自動校正邏輯（每日執行一次）
// 策略：保守微調，每次最多調整 5%，避免劇烈震盪
async function runAutoCalibration() {
  const today = new Date().toISOString().split('T')[0];
  if (today === calibrationBuffer.last_reset) return;

  const { fp_count, fn_count } = calibrationBuffer;
  const totalSignals = fp_count + fn_count;

  // 至少需要 5 筆回報才觸發校正
  if (totalSignals < 20) {
    calibrationBuffer.last_reset = today;
    calibrationBuffer.fp_count = 0;
    calibrationBuffer.fn_count = 0;
    calibrationBuffer.fp_domains = [];
    calibrationBuffer.fn_domains = [];
    return;
  }

  const fpRate = fp_count / totalSignals;
  const fnRate = fn_count / totalSignals;
  let adjusted = false;
  const changes = [];

  // FP 過高（>60% 的回報是 FP）→ 放寬閾值
  if (fpRate > 0.60) {
    const bump = 0.01; // v3.0 安全修正：從 2% 降到 1%
    if (ENGINE_THRESHOLDS.risk_l4 < 0.95) {
      ENGINE_THRESHOLDS.risk_l4 = Math.min(ENGINE_THRESHOLDS.risk_l4 + bump, 0.95);
      changes.push(`risk_l4 ↑ ${ENGINE_THRESHOLDS.risk_l4.toFixed(2)}`);
    }
    if (ENGINE_THRESHOLDS.risk_l3_high < 0.70) {
      ENGINE_THRESHOLDS.risk_l3_high = Math.min(ENGINE_THRESHOLDS.risk_l3_high + bump, 0.70);
      changes.push(`risk_l3_high ↑ ${ENGINE_THRESHOLDS.risk_l3_high.toFixed(2)}`);
    }
    adjusted = true;
  }

  // FN 過高（>60% 的回報是 FN）→ 收緊閾值
  if (fnRate > 0.60) {
    const drop = 0.01;
    if (ENGINE_THRESHOLDS.risk_l4 > 0.60) {
      ENGINE_THRESHOLDS.risk_l4 = Math.max(ENGINE_THRESHOLDS.risk_l4 - drop, 0.60);
      changes.push(`risk_l4 ↓ ${ENGINE_THRESHOLDS.risk_l4.toFixed(2)}`);
    }
    if (ENGINE_THRESHOLDS.risk_l3 > 0.10) {
      ENGINE_THRESHOLDS.risk_l3 = Math.max(ENGINE_THRESHOLDS.risk_l3 - drop, 0.10);
      changes.push(`risk_l3 ↓ ${ENGINE_THRESHOLDS.risk_l3.toFixed(2)}`);
    }
    adjusted = true;
  }

  if (adjusted) {
    await saveThresholds(`auto: FP=${fp_count}, FN=${fn_count}, ${changes.join(', ')}`);
    console.log(`[V2-AI] 自動校正完成：${changes.join(', ')}`);
  }

  // 重置 buffer
  calibrationBuffer.last_reset = today;
  calibrationBuffer.fp_count = 0;
  calibrationBuffer.fn_count = 0;
  calibrationBuffer.fp_domains = [];
  calibrationBuffer.fn_domains = [];
}

// 每小時檢查一次是否需要校正
setInterval(runAutoCalibration, 60 * 60 * 1000);

// 閾值 API：查看目前閾值（管理用）
// P3-04：管理 API 認證中介層
function requireAdmin(req, res, next) {
  const key = req.query.key || req.headers['x-admin-key'] || req.body?.key;
  if (key !== process.env.ADMIN_KEY) {
    return res.status(403).json({ status: 'error', message: 'unauthorized' });
  }
  next();
}

app.get('/v1/thresholds', requireAdmin, (req, res) => {
  res.json({
    status: 'ok',
    thresholds: ENGINE_THRESHOLDS,
    calibration_buffer: {
      fp_count: calibrationBuffer.fp_count,
      fn_count: calibrationBuffer.fn_count,
      fp_domains: calibrationBuffer.fp_domains.length,
      fn_domains: calibrationBuffer.fn_domains.length,
      last_reset: calibrationBuffer.last_reset,
    },
  });
});

// 手動校正 API（管理用）
app.post('/v1/thresholds/calibrate', requireAdmin, async (req, res) => {
  const { adjustments } = req.body;
  if (!adjustments || typeof adjustments !== 'object') {
    return res.status(400).json({ status: 'error', message: 'missing adjustments' });
  }

  const validKeys = Object.keys(ENGINE_THRESHOLDS).filter(k => k !== 'calibration_version' && k !== 'last_calibrated');
  const changes = [];

  for (const [k, v] of Object.entries(adjustments)) {
    if (validKeys.includes(k) && typeof v === 'number') {
      const old = ENGINE_THRESHOLDS[k];
      ENGINE_THRESHOLDS[k] = v;
      changes.push(`${k}: ${old} → ${v}`);
    }
  }

  if (changes.length > 0) {
    await saveThresholds(`manual: ${changes.join(', ')}`);
    return res.json({ status: 'ok', changes, thresholds: ENGINE_THRESHOLDS });
  }

  res.json({ status: 'ok', message: 'no changes', thresholds: ENGINE_THRESHOLDS });
});

// ════════════════════════════════════════
// P3-05：KNOWN_SAFE 動態管理 API
// ════════════════════════════════════════

// 查看白名單
app.get('/v1/whitelist', requireAdmin, (req, res) => {
  const list = [...KNOWN_SAFE].sort();
  res.json({ status: 'ok', count: list.length, domains: list });
});

// 新增白名單域名
app.post('/v1/whitelist/add', requireAdmin, async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains)) {
    return res.status(400).json({ status: 'error', message: 'domains must be an array' });
  }
  const added = [];
  for (const d of domains) {
    const clean = d.toLowerCase().replace(/^www\./, '').trim();
    if (clean && !KNOWN_SAFE.has(clean)) {
      KNOWN_SAFE.add(clean);
      added.push(clean);
    }
  }
  // 持久化到 DB
  if (added.length > 0) {
    try {
      await pool.query(
        `INSERT INTO whitelist_dynamic (domains, updated_at) VALUES ($1, NOW())
         ON CONFLICT (id) DO UPDATE SET domains = $1, updated_at = NOW()`,
        [JSON.stringify([...KNOWN_SAFE])]
      );
    } catch (e) { console.error('[WHITELIST] DB 儲存失敗:', e.message); }
  }
  console.log(`[WHITELIST] 新增 ${added.length} 筆: ${added.join(', ')}`);
  res.json({ status: 'ok', added, total: KNOWN_SAFE.size });
});

// 移除白名單域名
app.post('/v1/whitelist/remove', requireAdmin, async (req, res) => {
  const { domains } = req.body;
  if (!domains || !Array.isArray(domains)) {
    return res.status(400).json({ status: 'error', message: 'domains must be an array' });
  }
  const removed = [];
  for (const d of domains) {
    const clean = d.toLowerCase().replace(/^www\./, '').trim();
    if (KNOWN_SAFE.has(clean)) {
      KNOWN_SAFE.delete(clean);
      removed.push(clean);
    }
  }
  if (removed.length > 0) {
    try {
      await pool.query(
        `INSERT INTO whitelist_dynamic (domains, updated_at) VALUES ($1, NOW())
         ON CONFLICT (id) DO UPDATE SET domains = $1, updated_at = NOW()`,
        [JSON.stringify([...KNOWN_SAFE])]
      );
    } catch (e) { console.error('[WHITELIST] DB 儲存失敗:', e.message); }
  }
  console.log(`[WHITELIST] 移除 ${removed.length} 筆: ${removed.join(', ')}`);
  res.json({ status: 'ok', removed, total: KNOWN_SAFE.size });
});

// 啟動時從 DB 載入動態白名單（合併到硬編碼的 KNOWN_SAFE）
async function loadDynamicWhitelist() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS whitelist_dynamic (
        id INT PRIMARY KEY DEFAULT 1,
        domains JSONB NOT NULL DEFAULT '[]',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    const result = await pool.query('SELECT domains FROM whitelist_dynamic WHERE id = 1');
    if (result.rows.length > 0 && Array.isArray(result.rows[0].domains)) {
      let count = 0;
      for (const d of result.rows[0].domains) {
        if (!KNOWN_SAFE.has(d)) { KNOWN_SAFE.add(d); count++; }
      }
      if (count > 0) console.log(`[WHITELIST] 從 DB 載入 ${count} 筆動態白名單（總計 ${KNOWN_SAFE.size}）`);
    }
  } catch (e) { console.log('[WHITELIST] 動態白名單載入失敗:', e.message); }
}
setTimeout(loadDynamicWhitelist, 3000);

// v3.0：L1 驗證改版 — 新增欄位遷移（安全的 ALTER TABLE，欄位已存在會跳過）
async function migrateL1Schema() {
  const migrations = [
    `ALTER TABLE domains ADD COLUMN IF NOT EXISTS l1_tax_id VARCHAR(20)`,
    `ALTER TABLE domains ADD COLUMN IF NOT EXISTS l1_org_name VARCHAR(200)`,
    `ALTER TABLE domains ADD COLUMN IF NOT EXISTS l1_tier VARCHAR(20) DEFAULT 'basic'`,
  ];
  for (const sql of migrations) {
    try { await pool.query(sql); } catch (e) {
      // 某些 PG 版本不支援 IF NOT EXISTS，忽略 "already exists" 錯誤
      if (!e.message.includes('already exists')) console.error('[L1 Migration]', e.message);
    }
  }
  console.log('[L1] Schema 遷移完成');
}
setTimeout(migrateL1Schema, 5000);

// ════════════════════════════════════════
// URLScan：提交並等待結果
// ════════════════════════════════════════
async function urlscanSubmitAndFetch(domain) {
  try {
    const submit = await axios.post('https://urlscan.io/api/v1/scan/', {
      url: `https://${domain}`,
      visibility: 'unlisted'
    }, {
      headers: {
        'API-Key': process.env.URLSCAN_API_KEY,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    const uuid = submit.data.uuid;
    if (!uuid) return null;
    await new Promise(r => setTimeout(r, 15000));
    const result = await axios.get(`https://urlscan.io/api/v1/result/${uuid}/`, { timeout: 10000 });
    return result.data;
  } catch { return null; }
}

// ════════════════════════════════════════
// reCAPTCHA
// ════════════════════════════════════════
async function verifyRecaptcha(token) {
  try {
    const r = await axios.post('https://www.google.com/recaptcha/api/siteverify', null,
      { params: { secret: process.env.RECAPTCHA_SECRET, response: token }, timeout: 5000 });
    return r.data.success && r.data.score >= 0.5;
  } catch { return false; }
}

// ════════════════════════════════════════
// v3.0：短網址服務商名單（P-1 層）
// ════════════════════════════════════════
const SHORT_URL_SERVICES = new Set([
  'bit.ly', 'tinyurl.com', 'reurl.cc', 'pse.is', 'lihi.io',
  'is.gd', 't.co', 'goo.gl', 'ow.ly', 'rb.gy',
  'lihi1.com', 'lihi2.com', 'lihi3.com',
  'surl.li', 'rfrsh.me', 'shorturl.at',
]);

// v3.0 V2-06：多層短網址追蹤（最多 3 層，防止被利用為開放代理）
// P1-06：完整 SSRF 防護（防禦十進制/八進制/IPv6/IPv4-mapped 繞過）
function isPrivateIP(hostname) {
  // 明確的 localhost 變體
  if (['localhost', '0.0.0.0', '::1', '0', '127.1'].includes(hostname)) return true;
  
  // 封鎖十進制整數 IP（如 2130706433 = 127.0.0.1）
  if (/^\d+$/.test(hostname) && hostname.length > 3) return true;
  
  // IPv4 檢查
  if (net.isIPv4(hostname)) {
    const parts = hostname.split('.').map(Number);
    // 封鎖八進制格式（如 0177.0.0.1）
    if (hostname.split('.').some(p => p.startsWith('0') && p.length > 1)) return true;
    if (parts[0] === 10) return true;                              // 10.x.x.x
    if (parts[0] === 127) return true;                             // 127.x.x.x（全部）
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16-31.x.x
    if (parts[0] === 192 && parts[1] === 168) return true;         // 192.168.x.x
    if (parts[0] === 169 && parts[1] === 254) return true;         // 169.254.x.x (link-local / AWS metadata)
    if (parts[0] === 0) return true;                               // 0.x.x.x
    return false;
  }
  
  // IPv6 檢查
  if (net.isIPv6(hostname) || hostname.startsWith('[')) {
    const clean = hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (clean === '::1') return true;
    if (clean.startsWith('fe80:')) return true;   // link-local
    if (clean.startsWith('fc') || clean.startsWith('fd')) return true; // unique local
    // IPv4-mapped IPv6（如 ::ffff:127.0.0.1）
    if (clean.startsWith('::ffff:')) {
      const v4part = clean.replace('::ffff:', '');
      if (net.isIPv4(v4part)) return isPrivateIP(v4part);
    }
    return false;
  }
  
  return false;
}

async function resolveShortUrl(url, maxHops = 3) {
  const chain = [url]; // 記錄完整跳轉鏈
  let current = url;

  for (let hop = 0; hop < maxHops; hop++) {
    try {
      const fullUrl = current.startsWith('http') ? current : 'https://' + current;
      let location = null;

      try {
        const res = await axios.head(fullUrl, {
          maxRedirects: 0,
          timeout: 5000,
          validateStatus: s => s >= 200 && s < 400,
        });
        location = res.headers.location || null;
      } catch (err) {
        // axios 在 maxRedirects:0 時，3xx 會丟 error，但 response 裡有 location
        if (err.response && err.response.headers && err.response.headers.location) {
          location = err.response.headers.location;
        }
      }

      if (!location) break; // 沒有更多跳轉

      // 相對路徑轉絕對路徑
      if (location.startsWith('/')) {
        try {
          const base = new URL(fullUrl);
          location = base.origin + location;
        } catch {}
      }

      chain.push(location);

      // SSRF 防護：檢查跳轉目標是否為內網
      try {
        const targetHost = new URL(location.startsWith('http') ? location : 'https://' + location).hostname;
        if (isPrivateIP(targetHost)) {
          console.log(`[P-1] SSRF 攔截：${location} 指向內網，中止追蹤`);
          chain.pop(); // 移除危險的 URL
          break;
        }
      } catch { break; }

      // 檢查下一層是否仍然是短網址
      try {
        const nextDomain = new URL(location.startsWith('http') ? location : 'https://' + location).hostname
          .toLowerCase().replace(/^www\./, '');
        if (!SHORT_URL_SERVICES.has(nextDomain)) {
          // 到達最終目標，不再追蹤
          break;
        }
        current = location;
      } catch {
        break;
      }
    } catch {
      break;
    }
  }

  const finalUrl = chain[chain.length - 1];
  if (chain.length > 1) {
    console.log(`[P-1] 短網址追蹤（${chain.length - 1} 層）：${chain.join(' → ')}`);
  }

  return {
    resolved: chain.length > 1 ? finalUrl : null,
    chain,
    hops: chain.length - 1,
  };
}

// ════════════════════════════════════════
// API：主查詢 /v1/check（P1 快篩）
// ════════════════════════════════════════
app.post('/v1/check', async (req, res) => {
  let { value, source, skip_cache } = req.body;
  if (!value) return res.status(400).json({ status: 'error', message: '請提供網址' });

  // v3.0 V2-06：P-1 多層短網址追蹤
  const originalValue = value;
  let shortUrlChain = [];
  try {
    const checkDomain = extractDomain(value);
    if (SHORT_URL_SERVICES.has(checkDomain.toLowerCase().replace(/^www\./, ''))) {
      const { resolved, chain, hops } = await resolveShortUrl(value);
      shortUrlChain = chain;
      if (resolved) {
        console.log(`[P-1] 短網址追蹤完成：${hops} 層`);
        value = resolved;
      } else {
        console.log(`[P-1] 短網址解析失敗：${value}，使用原始 URL`);
      }
    }
  } catch {}

  const domain = extractDomain(value);
  let urlPath = '';
  try { urlPath = new URL(value.startsWith('http') ? value : 'https://' + value).pathname; } catch {}
  const clean = domain.toLowerCase().replace(/^www\./, '');

  // v2.3.1：快取查詢（除非明確要求跳過）
  if (!skip_cache) {
    const cached = getCachedResult(clean);
    if (cached) {
      stats.totalChecks++;
      stats.uniqueIPs.add(req.ip || 'unknown');
      return res.json({
        status: 'ok',
        cached: true,
        query: { domain: clean, url_path: urlPath || '/' },
        result: {
          level: cached.level,
          label: cached.label,
          should_block: cached.level >= 4,
          reasons: [{ code: 'CACHE', desc: '快取結果' }],
        },
        risk_score: cached.riskScore,
      });
    }
  }

  try {
    const gsbRes = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
      {
        client: { clientId: 'trustint', clientVersion: '2.2' },
        threatInfo: {
          threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: value }]
        }
      }, { timeout: 5000 }
    );
    const gsbHit = !!(gsbRes.data.matches && gsbRes.data.matches.length > 0);
    const result = getLevel(gsbHit, domain, urlPath);
    // v2.3.1：寫入快取
    setCachedResult(clean, result.level, result.label);
    // v3.0：警示
    const warnings = detectWarningKeywords(clean);
    return res.json({ status: 'ok', query: { domain, url_path: urlPath }, result, warnings });
  } catch {
    const result = getLevel(false, domain, urlPath);
    setCachedResult(clean, result.level, result.label);
    const warnings = detectWarningKeywords(clean);
    return res.json({ status: 'ok', query: { domain, url_path: urlPath }, result, warnings });
  }
});

// ════════════════════════════════════════════════════════════════
// P3-06：Request Coalescing（防止 Cache Stampede）
// 同一個 domain 的多個並行 deep-analyze 請求共用同一個 Promise
// ════════════════════════════════════════════════════════════════
const pendingDeepAnalyze = new Map(); // domain -> Promise

// ════════════════════════════════════════════════════════════════
// API：深度分析 /v1/deep-analyze（P0→P6 完整引擎 v2.3.1）
// v2.3.1 新增：DOM-Lite 整合（ATK-1 防禦）
// ════════════════════════════════════════════════════════════════
app.post('/v1/deep-analyze', async (req, res) => {
  let { domain, url_path, referrer, utm_source, utm_medium, dom_scan } = req.body;
  if (!domain) return res.status(400).json({ status: 'error' });

  // v3.0 V2-06：P-1 多層短網址追蹤（deep-analyze）
  let shortUrlChain = [];
  try {
    const checkHost = domain.toLowerCase().replace(/^www\./, '');
    if (SHORT_URL_SERVICES.has(checkHost)) {
      const { resolved, chain, hops } = await resolveShortUrl('https://' + domain + (url_path || ''));
      shortUrlChain = chain;
      if (resolved) {
        console.log(`[P-1] deep-analyze 短網址追蹤：${hops} 層`);
        const parsedResolved = new URL(resolved);
        domain = parsedResolved.hostname;
        url_path = parsedResolved.pathname + parsedResolved.search;
      }
    }
  } catch {}

  const clean = domain.toLowerCase().replace(/^www\./, '');
  const cleanBase = clean.replace(TLD_STRIP_RE, '');
  const urlPath = url_path || '';
  const tld = '.' + clean.split('.').pop();
  const checks = [];
  const triggered = [];

  // ── L1 官方驗證快速通道（V1-22）──
  if (l1VerifiedDomainsCache.has(clean)) {
    const l1Data = l1Verifications.get(clean);
    console.log(`[TRACE] ${JSON.stringify({ domain: clean, decision_path: 'L1_VERIFIED → L1', level: 1, engine_version: '3.0', timestamp: new Date().toISOString() })}`);
    res.locals.trustintLevel = 1;
    return res.json({
      status: 'ok',
      report: buildPublicReport(clean, ['🏆 L1 官方已驗證'], '🏆 此網域已通過 TrustInt 官方驗證'),
      level: 1, 
      newLevel: 1, 
      newLabel: '官方已驗證',
      should_block: false, 
      risk_score: 0,
      risk_groups: { age: 'safe', whois: 'safe', asn: 'safe', ssl: 'safe', reputation: 'safe', behavior: 'safe' },
      l1_verified: true,
      l1_expires: l1Data?.expires ? new Date(l1Data.expires).toISOString() : null
    });
  }

  // ── A群：黑名單快速通道（P1 Hard Rules）──
  // 165 反詐騙黑名單
  if (npaBlacklist.has(clean)) {
    console.log(`[TRACE] ${JSON.stringify({ domain: clean, decision_path: 'NPA_165 → L5', level: 5, engine_version: '3.0', timestamp: new Date().toISOString() })}`);
    res.locals.trustintLevel = 5;
    return res.json({
      status: 'ok',
      report: buildPublicReport(clean, ['🔴 命中 165 反詐騙黑名單'], '🚨 此網域已被警政署 165 列為詐騙網站'),
      newLevel: 5, newLabel: '多項安全指標異常',
      should_block: true, risk_score: 1.0,
      risk_groups: { age: 'critical', whois: 'critical', asn: 'critical', ssl: 'critical', reputation: 'critical', behavior: 'critical' },
      triggered: ['A1_NPA_165'],
    });
  }
  // OpenPhish 釣魚資料庫
  if (openPhishList.has(clean)) {
    console.log(`[TRACE] ${JSON.stringify({ domain: clean, decision_path: 'OPENPHISH → L5', level: 5, engine_version: '3.0', timestamp: new Date().toISOString() })}`);
    res.locals.trustintLevel = 5;
    return res.json({
      status: 'ok',
      report: buildPublicReport(clean, ['🔴 命中 OpenPhish 釣魚資料庫'], '🚨 此網域已被國際釣魚資料庫標記'),
      newLevel: 5, newLabel: '多項安全指標異常',
      should_block: true, risk_score: 1.0,
      risk_groups: { age: 'critical', whois: 'critical', asn: 'critical', ssl: 'critical', reputation: 'critical', behavior: 'critical' },
      triggered: ['A2_OPENPHISH'],
    });
  }

  // ── 白名單快速通道：已知安全網域不需深度分析 ──
  const isKnownSafeDomain = KNOWN_SAFE.has(clean) ||
    Array.from(KNOWN_SAFE).some(s => clean.endsWith('.' + s));
  if (isKnownSafeDomain) {
    console.log(`[TRACE] ${JSON.stringify({ domain: clean, decision_path: 'WHITELIST → L2', level: 2, engine_version: '3.0', timestamp: new Date().toISOString() })}`);
    res.locals.trustintLevel = 2;
    return res.json({
      status: 'ok',
      report: buildPublicReport(clean, ['✅ 已知安全網域'], '✅ 已知安全網域，無需深度分析'),
      newLevel: 2, newLabel: '安心信任',
      should_block: false, risk_score: 0,
      risk_groups: { age: 'safe', whois: 'safe', asn: 'safe', ssl: 'safe', reputation: 'safe', behavior: 'safe' },
    });
  }

  // ── P3-06：Request Coalescing（防止同一 domain 的並行請求同時打外部 API）──
  // 如果同一個 domain 已有進行中的 deep-analyze，等待它完成並使用快取結果
  if (pendingDeepAnalyze.has(clean)) {
    try {
      console.log(`[P3-06] 合併請求：${clean}（等待進行中的分析完成）`);
      const cachedResult = await pendingDeepAnalyze.get(clean);
      if (cachedResult) {
        res.locals.trustintLevel = cachedResult.newLevel;
        return res.json(cachedResult);
      }
    } catch {}
    // 如果等待失敗，繼續正常流程
  }

  // 建立 dedup Promise（在外部 API 呼叫前）
  let resolveDedup;
  const dedupPromise = new Promise(r => { resolveDedup = r; });
  pendingDeepAnalyze.set(clean, dedupPromise);
  // 30 秒後自動清理（避免 Promise 永遠掛著）
  const dedupCleanup = setTimeout(() => pendingDeepAnalyze.delete(clean), 30000);

  // ── 並行查詢外部 API ──
  const [ipRes, whoisRes, vtRes, dnsRes, ipqsRes, sslRes] = await Promise.allSettled([
    axios.get(`http://ip-api.com/json/${clean}?fields=status,country,countryCode,isp,org,hosting,proxy,as,query`, { timeout: 5000 }),
    axios.get(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${process.env.WHOIS_API_KEY}&domainName=${clean}&outputFormat=JSON`, { timeout: 8000 }),
    axios.get(`https://www.virustotal.com/api/v3/domains/${clean}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }, timeout: 8000
    }),
    axios.get(`https://dns.google/resolve?name=${clean}&type=A`, { timeout: 5000 }),
    axios.get(`https://www.ipqualityscore.com/api/json/url/${process.env.IPQS_API_KEY}/${encodeURIComponent('https://' + clean)}`, { timeout: 8000 }),
    checkSSLCertificate(clean)  // v2.4：SSL 憑證檢查
  ]);

  // ── 初始化因子（v2.4：加入 SSL 憑證詳細欄位）──
  const factors = {
    domainAgeDays: null, whoisHidden: false, privacyProtection: false,
    whoisVisible: false, isHighAbuseRegistrar: false,
    countryCode: '', asnTier: 'neutral', asnString: '',
    vtMalicious: 0, vtSuspicious: 0,
    abuseScore: 0, hasFishingKeyword: false, hasMultiSubdomain: false,
    isDGA: false, registrar: '', tld,
    certAgeDays: null, hasHttps: true, certType: 'DV',
    certOrg: null, certIssuer: null,  // v2.4 新增
    reputationInconsistency: false,
    ipqsScore: 0, ipqsPhishing: false, ipqsMalware: false,
    apiFailCount: 0,
    hasCriticalSignal: false, hasCriticalCluster: false, hasBHR: false,
    // URLScan 結果
    hasPasswordField: false, formActionExternal: false,
    hasMaliciousScript: false, hasIframeTrusted: false,
    hasMetaRedirect: false, redirectCount: 0,
    pageTitle: '', pageMalicious: false,
    // v2.2 新增
    isOnePage: false, hasClipboardAPI: false, hasSocialLure: false,
    hasAdTraffic: false, hasRefundKeywords: false, hasOAuthFlow: false,
    hasFakeUpdateUI: false, hasCountdown: false, hasCODPayment: false,
    pathEntropy: 0, pathLength: 0, urlLength: (url_path || '').length,
    semanticResult: null,
    // v2.3.1 新增：DOM-Lite 掃描結果（ATK-1 防禦）
    hasCreditCardField: false, hasOTPField: false,
    domScanBrandMentions: [], domScanFormActions: [],
    hasInvestKeywords: false, hasFakeShopSignals: false,
  };

  // ══════════════════════════════════════
  // v2.3.1：DOM-Lite 整合（ATK-1 防禦）
  // 「乾淨殼 + 髒內容」攻擊的防禦關鍵
  // ══════════════════════════════════════
  if (dom_scan) {
    // 直接從前端 content.js 傳來的 DOM 掃描結果
    factors.hasPasswordField = dom_scan.hasPasswordField || false;
    factors.hasCreditCardField = dom_scan.hasCreditCardField || false;
    factors.hasOTPField = dom_scan.hasOTPField || false;
    factors.hasSocialLure = dom_scan.hasSocialLure || false;
    factors.hasInvestKeywords = dom_scan.hasInvestKeywords || false;
    factors.hasFakeShopSignals = dom_scan.hasFakeShopSignals || false;
    factors.hasCountdown = dom_scan.hasCountdown || false;
    factors.domScanBrandMentions = dom_scan.brandMentions || [];
    factors.domScanFormActions = dom_scan.formActions || [];

    // 記錄 DOM 掃描偵測結果
    if (factors.hasPasswordField) checks.push('⚠️ DOM 偵測：含密碼輸入欄位');
    if (factors.hasCreditCardField) checks.push('🔴 DOM 偵測：含信用卡輸入欄位');
    if (factors.hasOTPField) checks.push('⚠️ DOM 偵測：含 OTP 驗證碼欄位');
    if (factors.hasSocialLure) checks.push('⚠️ DOM 偵測：含社交誘導（加 LINE/WhatsApp）');
    if (factors.hasInvestKeywords) checks.push('🔴 DOM 偵測：含投資詐騙關鍵字');
    if (factors.hasFakeShopSignals) checks.push('⚠️ DOM 偵測：含假電商特徵');
    if (factors.hasCountdown) checks.push('⚠️ DOM 偵測：含倒數計時器');
    if (factors.domScanBrandMentions.length > 0) {
      checks.push(`⚠️ DOM 偵測：頁面提及品牌 [${factors.domScanBrandMentions.join(', ')}]`);
    }
    if (factors.domScanFormActions.length > 0) {
      checks.push(`🔴 DOM 偵測：表單資料送往外部 [${factors.domScanFormActions.join(', ')}]`);
      factors.formActionExternal = true;
    }

    // DOM-Lite 觸發的額外規則
    // BHR-DOM-1：新網域 + 信用卡欄位 → 高風險
    if (factors.hasCreditCardField) {
      triggered.push('DOM_CREDIT_CARD');
    }
    // BHR-DOM-2：投資關鍵字 + 社交誘導 → 殺豬盤特徵
    if (factors.hasInvestKeywords && factors.hasSocialLure) {
      triggered.push('DOM_INVEST_SOCIAL');
    }
    // BHR-DOM-3：假電商 + 倒數計時 → 一頁式詐騙特徵
    if (factors.hasFakeShopSignals && factors.hasCountdown) {
      triggered.push('DOM_FAKE_SHOP_COUNTDOWN');
      factors.isOnePage = true;  // 假電商 + 倒數 = 一頁式特徵
    }
    // BHR-DOM-4：品牌提及 + 非官方域名 → 品牌仿冒
    if (factors.domScanBrandMentions.length > 0) {
      const mentionedBrand = factors.domScanBrandMentions[0];
      const isOfficial = BRAND_DOMAINS.some(b => 
        b.brand.toLowerCase() === mentionedBrand.toLowerCase() && 
        (clean === b.official || clean.endsWith('.' + b.official) ||
         (b.aliases && b.aliases.some(a => clean === a || clean.endsWith('.' + a))))
      );
      if (!isOfficial) {
        triggered.push('DOM_BRAND_MENTION_UNOFFICIAL');
        checks.push(`🔴 DOM 偵測：頁面聲稱是 ${mentionedBrand}，但非官方域名`);
      }
    }

    // v3.0 BHR-IMG：低文字密度 + 高圖片密度 + 新網域 → L4 地板
    // 圖片化詐騙的輕量偵測（不需要 OCR）
    if (dom_scan.isLowTextHighImage) {
      checks.push(`⚠️ DOM 偵測：頁面文字極少（${dom_scan.visibleTextLength || 0}字）但圖片密集（${dom_scan.imgCount || 0}張）`);
      triggered.push('BHR_IMG_LOW_TEXT');
    }
  }

  // 計算 path entropy
  if (urlPath) {
    const pathPart = urlPath.replace(/^\//, '');
    factors.pathEntropy = shannonEntropy(pathPart);
    factors.pathLength = pathPart.length;
  }

  // 偵測廣告流量
  if (utm_source) {
    const src = utm_source.toLowerCase();
    if (['tiktok','facebook','fb','ig','instagram','meta'].includes(src)) {
      factors.hasAdTraffic = true;
    }
  }
  if (utm_medium) {
    const med = utm_medium.toLowerCase();
    if (['paid','ads','cpc','cpm','ad'].includes(med)) {
      factors.hasAdTraffic = true;
    }
  }

  // ══════════════════════════════════════
  // 處理外部 API 結果
  // ══════════════════════════════════════

  // ── 處理 IP/ASN（v2.2：ASN 層級判斷）──
  let resolvedIp = null;
  if (ipRes.status === 'fulfilled' && ipRes.value.data && ipRes.value.data.status !== 'fail') {
    const ip = ipRes.value.data;
    factors.countryCode = ip.countryCode || '';
    factors.asnString = ip.as || '';
    resolvedIp = ip.query;

    // v2.2：ASN 分級
    factors.asnTier = classifyASN(ip.as);

    if (factors.asnTier === 'bulletproof') {
      checks.push(`🔴 IP 位於已知 Bulletproof Hosting ASN：${ip.as}`);
    } else if (factors.asnTier === 'high_abuse') {
      checks.push(`⚠️ IP 位於高濫用 ASN：${ip.as}`);
    } else if (factors.asnTier === 'large_cloud') {
      checks.push(`ℹ️ 大型雲端 ASN：${ip.isp || ip.org || ip.as}`);
    } else if (ip.country) {
      checks.push(`✅ IP 國家：${ip.country}（ASN: ${ip.as || '未知'}）`);
      // 僅在已知安全國家+非個人主機段時才標為 safe
      const SAFE_COUNTRIES = ['TW','JP','US','CA','GB','DE','FR','AU','SG','KR'];
      if (SAFE_COUNTRIES.includes(ip.countryCode) && !ip.hosting) {
        factors.asnTier = 'safe';
      }
    }

    if (ip.proxy) {
      checks.push('⚠️ 偵測到代理/VPN 使用');
      triggered.push('PROXY_DETECTED');
    }
    if (ip.hosting) checks.push(`ℹ️ 主機服務商：${ip.isp || ip.org || '未知'}`);
  } else {
    checks.push('⚠️ 無法取得 IP 資訊');
  }

  // ── 處理 WHOIS ──
  if (whoisRes.status === 'fulfilled' && whoisRes.value.data) {
    try {
      const whois = whoisRes.value.data.WhoisRecord;
      const created   = whois?.createdDate || whois?.registryData?.createdDate;
      const updated   = whois?.updatedDate || whois?.registryData?.updatedDate;
      const registrar = whois?.registrarName || whois?.registryData?.registrarName || '';
      factors.registrar = registrar;

      if (created) {
        const ageDays = (Date.now() - new Date(created)) / 86400000;
        factors.domainAgeDays = ageDays;
        if (ageDays < 14)       checks.push(`🔴 網域極新（${Math.floor(ageDays)} 天），詐騙高風險`);
        else if (ageDays < 90)  checks.push(`⚠️ 網域未滿 3 個月（${Math.floor(ageDays)} 天）`);
        else if (ageDays < 365) checks.push(`ℹ️ 網域約 ${Math.floor(ageDays/30)} 個月`);
        else                    checks.push(`✅ 網域已存在 ${Math.floor(ageDays/365)} 年以上`);

        // 信譽不一致偵測
        if (ageDays > 365 && updated) {
          const updateDays = (Date.now() - new Date(updated)) / 86400000;
          if (updateDays < 30) {
            factors.reputationInconsistency = true;
            checks.push('⚠️ 老網域近期剛更新（信譽不一致偵測）');
            triggered.push('REPUTATION_INCONSISTENCY');
          }
        }
      }

      // WHOIS 隱藏判斷
      const contactEmail = whois?.registrantContact?.email || '';
      if (!contactEmail || contactEmail.includes('privacy') || contactEmail.includes('protect') || contactEmail.includes('proxy')) {
        factors.whoisHidden = true;
        checks.push('⚠️ WHOIS 聯絡資訊隱藏');
      } else {
        factors.whoisVisible = true;
        checks.push('✅ WHOIS 資訊可見');
      }

      // Privacy Protection
      const privacyKeywords = ['privacy', 'protect', 'whoisguard', 'domains by proxy', 'perfect privacy'];
      if (registrar && privacyKeywords.some(k => registrar.toLowerCase().includes(k))) {
        factors.privacyProtection = true;
      }

      if (registrar) checks.push(`ℹ️ 註冊商：${registrar}`);

      // 高濫用率註冊商判斷
      const regLower = registrar.toLowerCase();
      if (RISKY_REGISTRARS_L1.some(r => regLower.includes(r))) {
        checks.push(`⚠️ 高濫用率註冊商（第一級）：${registrar}`);
        triggered.push('RISKY_REGISTRAR_L1');
        factors.isHighAbuseRegistrar = true;
      } else if (RISKY_REGISTRARS_L2.some(r => regLower.includes(r))) {
        checks.push(`⚠️ 高濫用率註冊商（第二級）：${registrar}`);
        triggered.push('RISKY_REGISTRAR_L2');
        factors.isHighAbuseRegistrar = true;
      } else if (RISKY_REGISTRARS_WEAK.some(r => regLower.includes(r))) {
        checks.push(`ℹ️ 註冊商 ${registrar}（弱負面因子）`);
      }
    } catch { checks.push('⚠️ 無法解析 WHOIS'); }
  } else {
    checks.push('⚠️ 無法取得 WHOIS');
    factors.apiFailCount++;
  }

  // ── 處理 VirusTotal ──
  if (vtRes.status === 'fulfilled' && vtRes.value.data) {
    try {
      const stats = vtRes.value.data.data?.attributes?.last_analysis_stats;
      if (stats) {
        factors.vtMalicious  = stats.malicious  || 0;
        factors.vtSuspicious = stats.suspicious || 0;
        if (factors.vtMalicious >= 5) {
          checks.push(`🔴 VirusTotal：${factors.vtMalicious} 個引擎標記惡意`);
          triggered.push('VT_HIGH');
          factors.hasCriticalSignal = true;
        } else if (factors.vtMalicious >= 3) {
          checks.push(`⚠️ VirusTotal：${factors.vtMalicious} 個引擎標記惡意`);
          triggered.push('VT_MID');
          factors.hasCriticalSignal = true;
        } else if (factors.vtMalicious > 0) {
          checks.push(`⚠️ VirusTotal：${factors.vtMalicious} 個惡意，${factors.vtSuspicious} 個可疑`);
        } else {
          checks.push('✅ VirusTotal：全部引擎安全');
        }
      }
    } catch { checks.push('⚠️ 無法取得 VirusTotal'); }
  } else {
    checks.push('⚠️ 無法取得 VirusTotal');
    factors.apiFailCount++;
  }

  // ── 處理 IPQualityScore ──
  if (ipqsRes.status === 'fulfilled' && ipqsRes.value.data) {
    try {
      const ipqs = ipqsRes.value.data;
      const ipqsRisk = typeof ipqs.risk_score === 'number' ? ipqs.risk_score : null;
      factors.ipqsScore    = ipqsRisk || 0;
      factors.ipqsPhishing = ipqs.phishing   || false;
      factors.ipqsMalware  = ipqs.malware    || false;

      if (ipqsRisk === null) {
        checks.push('⚠️ IPQualityScore：無法取得風險分數');
        factors.apiFailCount++;
      } else if (ipqsRisk >= 90 || ipqs.phishing || ipqs.malware) {
        checks.push(`🔴 IPQualityScore：風險 ${ipqsRisk}分${ipqs.phishing ? '，釣魚確認' : ''}${ipqs.malware ? '，惡意軟體' : ''}`);
        triggered.push('IPQS_HIGH');
        factors.hasCriticalSignal = true;
      } else if (ipqsRisk >= 75) {
        checks.push(`⚠️ IPQualityScore：風險 ${ipqsRisk}分`);
        triggered.push('IPQS_MID');
      } else if (ipqsRisk >= 60) {
        checks.push(`⚠️ IPQualityScore：風險 ${ipqsRisk}分（偏高）`);
        triggered.push('IPQS_ELEVATED');
      } else {
        checks.push(`✅ IPQualityScore：風險 ${ipqsRisk}分`);
      }

      if (ipqs.suspicious) checks.push('⚠️ IPQualityScore：標記為可疑');
      if (ipqs.adult) checks.push('ℹ️ IPQualityScore：成人內容網站');
    } catch { checks.push('⚠️ 無法解析 IPQualityScore'); factors.apiFailCount++; }
  } else {
    checks.push('⚠️ 無法取得 IPQualityScore');
    factors.apiFailCount++;
  }

  // ── v2.4：SSL 憑證檢查（V1-09 BHR-OV）──
  if (sslRes.status === 'fulfilled' && sslRes.value) {
    const ssl = sslRes.value;
    factors.hasHttps = ssl.hasHttps;
    factors.certType = ssl.certType || 'DV';
    factors.certOrg = ssl.certOrg || null;
    factors.certIssuer = ssl.certIssuer || null;
    factors.certAgeDays = ssl.certAgeDays;
    
    if (!ssl.hasHttps) {
      checks.push('🔴 SSL：無 HTTPS 連線');
      triggered.push('NO_HTTPS');
      factors.hasCriticalSignal = true;
    } else if (ssl.certType === 'EV') {
      checks.push(`✅ SSL：EV 憑證（${ssl.certOrg || '組織未知'}）`);
    } else if (ssl.certType === 'OV') {
      checks.push(`✅ SSL：OV 憑證（${ssl.certOrg || '組織未知'}）`);
    } else {
      checks.push(`ℹ️ SSL：DV 憑證`);
      if (ssl.certAgeDays !== null && ssl.certAgeDays < 30) {
        checks.push(`⚠️ SSL：憑證簽發僅 ${ssl.certAgeDays} 天`);
      }
    }
  } else {
    checks.push('⚠️ 無法取得 SSL 憑證資訊');
  }

  // ── AbuseIPDB ──
  const ipForAbuse = resolvedIp || (dnsRes.status === 'fulfilled' ? dnsRes.value.data?.Answer?.[0]?.data : null);
  if (ipForAbuse) {
    try {
      const abuse = await axios.get('https://api.abuseipdb.com/api/v2/check', {
        params: { ipAddress: ipForAbuse, maxAgeInDays: 90 },
        headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' },
        timeout: 5000
      });
      factors.abuseScore = abuse.data?.data?.abuseConfidenceScore || 0;
      const total = abuse.data?.data?.totalReports || 0;
      if (factors.abuseScore >= 75) {
        checks.push(`🔴 AbuseIPDB：IP 風險 ${factors.abuseScore}%，${total} 筆通報`);
        factors.hasCriticalSignal = true;
        triggered.push('ABUSE_HIGH');
      } else if (factors.abuseScore >= 50) {
        checks.push(`⚠️ AbuseIPDB：IP 風險 ${factors.abuseScore}%`);
      } else if (factors.abuseScore > 0) {
        checks.push(`⚠️ AbuseIPDB：IP 風險 ${factors.abuseScore}%`);
      } else {
        checks.push('✅ AbuseIPDB：無通報紀錄');
      }

      // CC10：惡意鄰居（v2.3：排除大型雲端 ASN，共享主機環境誤殺率極高）
      const subnet = ipForAbuse.split('.').slice(0, 3).join('.');
      if (npaIpSubnets.has(subnet) && factors.asnTier !== 'large_cloud') {
        checks.push('⚠️ IP 與 165 黑名單惡意 IP 同網段（CC10 惡意鄰居）');
        triggered.push('CC10_EVIL_NEIGHBOR');
      } else if (npaIpSubnets.has(subnet) && factors.asnTier === 'large_cloud') {
        checks.push('ℹ️ IP 與 165 黑名單同網段，但屬大型雲端 ASN（CC10 不觸發）');
      }
    } catch { checks.push('⚠️ 無法取得 AbuseIPDB'); }
  }

  // ══════════════════════════════════════
  // 行為特徵分析
  // ══════════════════════════════════════
  factors.hasFishingKeyword = FISHING_KEYWORDS.some(k => clean.includes(k));
  factors.hasMultiSubdomain = (clean.match(/\./g) || []).length >= 3;
  const domainPart = clean.split('.')[0];
  factors.isDGA = shannonEntropy(domainPart) > 3.8 && domainPart.length > 8;

  if (factors.hasFishingKeyword)
    checks.push(`⚠️ 含釣魚關鍵字：${FISHING_KEYWORDS.filter(k => clean.includes(k)).join(', ')}`);
  else
    checks.push('✅ 不含常見釣魚關鍵字');

  if (factors.isDGA)
    checks.push(`⚠️ 網域字元疑似隨機亂碼（DGA 特徵，entropy: ${shannonEntropy(domainPart).toFixed(2)}）`);
  if (factors.hasMultiSubdomain)
    checks.push('⚠️ 多層子網域結構');

  // TLD 風險標記
  if (TLD_TIER1_DIRECT_L4.has(tld))
    checks.push(`🔴 使用免費高濫用 TLD（${tld}），直接設定 L4 地板`);
  else if (TLD_TIER2_STRONG.has(tld))
    checks.push(`⚠️ 使用高濫用率 TLD（${tld}）`);

  if (clean.includes('xn--'))
    checks.push('⚠️ 含 Punycode 國際化字元（同形異義字攻擊風險）');

  // 品牌仿冒確認
  const spoofResult = isBrandSpoof(clean, cleanBase);
  if (spoofResult) {
    checks.push(`🔴 疑似仿冒 ${spoofResult.brand} 官方網域`);
    triggered.push('BRAND_SPOOF_CONFIRMED');
    factors.hasCriticalSignal = true;
  }

  // 寄生攻擊
  if (isParasitePlatform(clean)) {
    checks.push('⚠️ 高信譽平台用戶內容頁面（寄生攻擊風險）');
    triggered.push('PARASITE_ATTACK');
  }

  // ══════════════════════════════════════
  // URLScan 分析
  // ══════════════════════════════════════
  let urlscanData = null;
  try {
    const searchRes = await axios.get(
      `https://urlscan.io/api/v1/search/?q=domain:${clean}&size=1`,
      { headers: { 'API-Key': process.env.URLSCAN_API_KEY }, timeout: 8000 }
    );
    if (searchRes.data?.results?.length > 0) {
      const latest = searchRes.data.results[0];
      const scanAge = (Date.now() - new Date(latest.task?.time)) / 86400000;
      if (scanAge < 30) {
        urlscanData = latest;
        checks.push(`ℹ️ URLScan：使用 ${Math.floor(scanAge)} 天前的掃描結果`);
      }
    }
  } catch {}

  if (!urlscanData && (factors.hasFishingKeyword || factors.isDGA || factors.hasAdTraffic)) {
    checks.push('ℹ️ URLScan：提交新掃描（需等待約 15 秒）');
    urlscanData = await urlscanSubmitAndFetch(clean);
  }

  if (urlscanData) {
    try {
      const page = urlscanData.page || {};
      const lists = urlscanData.lists || {};
      const verdicts = urlscanData.verdicts || {};

      factors.pageTitle = page.title || '';

      // 惡意判定
      if (verdicts.overall?.malicious || verdicts.urlscan?.malicious) {
        checks.push('🔴 URLScan：頁面判定為惡意');
        triggered.push('URLSCAN_MALICIOUS');
        factors.pageMalicious = true;
        factors.hasCriticalSignal = true;
      } else if (verdicts.overall?.score > 50) {
        checks.push(`⚠️ URLScan：可疑分數 ${verdicts.overall.score}`);
      }

      // redirect chain
      factors.redirectCount = (lists.urls || []).length - 1;
      if (factors.redirectCount >= 4) {
        checks.push(`⚠️ URLScan：偵測到 ${factors.redirectCount} 層跳轉`);
        triggered.push('REDIRECT_CHAIN_HIGH');
      } else if (factors.redirectCount >= 3) {
        checks.push(`⚠️ URLScan：${factors.redirectCount} 層跳轉`);
        triggered.push('REDIRECT_CHAIN_MID');
      }

      // 惡意腳本
      const scripts = lists.scripts || [];
      if (scripts.some(s => s.includes('keylog') || s.includes('stealer'))) {
        checks.push('🔴 URLScan：偵測到鍵盤側錄或竊取腳本');
        triggered.push('MALICIOUS_SCRIPT');
        factors.hasMaliciousScript = true;
        factors.hasCriticalSignal = true;
      }

      // v2.2：Clipboard API 偵測（CC20）
      if (scripts.some(s => s.includes('clipboard') || s.includes('execCommand'))) {
        // 如果同時有加密貨幣語意
        const pageText = (factors.pageTitle + ' ' + (page.url || '')).toLowerCase();
        if (['wallet','btc','eth','usdt','bitcoin','ethereum','crypto','tether'].some(k => pageText.includes(k))) {
          factors.hasClipboardAPI = true;
          checks.push('🔴 偵測到 Clipboard API + 加密貨幣語意（CC20）');
          triggered.push('CC20_CLIPBOARD_HIJACK');
        }
      }

      // iframe 嵌入（BHR6：點擊劫持）
      if ((lists.urls || []).some(u => {
        try {
          const d = new URL(u).hostname;
          return KNOWN_SAFE.has(d) && d !== clean;
        } catch { return false; }
      })) {
        checks.push('🔴 URLScan：iframe 嵌入已知機構頁面（點擊劫持風險）');
        triggered.push('BHR6_CLICKJACK');
        factors.hasIframeTrusted = true;
        factors.hasBHR = true;
      }

      // 品牌 title 比對（BHR1/BHR3）
      if (factors.pageTitle && spoofResult) {
        const titleLower = factors.pageTitle.toLowerCase();
        if (BRAND_DOMAINS.some(b => titleLower.includes(b.brand.toLowerCase()) || titleLower.includes(b.official.split('.')[0]))) {
          checks.push(`🔴 URLScan：頁面標題聲稱是品牌網站（${factors.pageTitle}）`);
          triggered.push('BHR1_VISUAL_SPOOF');
          factors.hasBHR = true;
        }
      }

      // v2.2：一頁式偵測（CC19）
      factors.isOnePage = isOnePageStructure(urlscanData);
      if (factors.isOnePage) {
        checks.push('⚠️ 偵測到一頁式網站結構（無導航/分類頁面）');
        triggered.push('ONE_PAGE_STRUCTURE');
      }
    } catch { checks.push('⚠️ URLScan 結果解析失敗'); }
  } else {
    checks.push('ℹ️ URLScan：無可用掃描資料');
  }

  // ══════════════════════════════════════
  // 語意分析（P0 前置）
  // ══════════════════════════════════════
  const textForSemantic = [
    factors.pageTitle,
    clean,
    urlPath,
  ].join(' ');
  factors.semanticResult = analyzeSemantics(textForSemantic);

  // 檢查特定語意類別
  const semCats = factors.semanticResult.categories;
  if (semCats.includes('refund'))    factors.hasRefundKeywords = true;
  if (semCats.includes('social'))    factors.hasSocialLure = true;
  if (semCats.includes('fake_shop')) factors.hasCODPayment = true;

  if (factors.semanticResult.riskAdd > 0) {
    checks.push(`⚠️ 語意分析：命中類別 [${semCats.join(', ')}]，risk 加權 +${factors.semanticResult.riskAdd}`);
  }

  // ══════════════════════════════════════
  // P0：語意 + 行為即時判斷層（最高優先級）
  // ══════════════════════════════════════
  let p0Hit = null;

  // 判斷是否為合法金融機構（P0 排除用）
  const isLegitFinancial = LEGIT_FINANCIAL_DOMAINS.has(clean) ||
    Array.from(LEGIT_FINANCIAL_DOMAINS).some(d => clean.endsWith('.' + d));
  const isOldDomainOnSafeASN = factors.domainAgeDays !== null && factors.domainAgeDays > 365 &&
    (factors.asnTier === 'safe' || factors.asnTier === 'large_cloud');

  // P0-1：金流意圖 + 新網域
  if (!p0Hit && factors.domainAgeDays !== null && factors.domainAgeDays < 30 &&
      semCats.includes('phishing') && factors.semanticResult.riskAdd >= 0.2) {
    p0Hit = { code: 'P0-1', desc: '金流意圖 + 極新網域（< 30 天）' };
  }

  // P0-2：詐騙語意 + 廣告來源 + 金流
  if (!p0Hit && factors.hasAdTraffic &&
      (semCats.includes('lure') || semCats.includes('gov_fake')) &&
      semCats.includes('phishing')) {
    p0Hit = { code: 'P0-2', desc: '詐騙語意 + 廣告來源 + 金流意圖' };
  }

  // P0-3：投資語意 + 封閉式登入（v2.2：加排除條件）
  if (!p0Hit && semCats.includes('invest') &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 365 &&
      !isLegitFinancial && !isOldDomainOnSafeASN) {
    // 只有在非合法金融 + 非老網域安全ASN 時才觸發
    if (factors.isOnePage || (factors.pageTitle && !factors.pageTitle.includes('about'))) {
      p0Hit = { code: 'P0-3', desc: '投資語意 + 封閉式登入（非合法金融機構）' };
    }
  }

  // P0-4：假退款/假客服語意（v2.2 新增）
  if (!p0Hit && semCats.includes('refund') &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90 &&
      !isLegitFinancial) {
    p0Hit = { code: 'P0-4', desc: '假退款/假客服語意 + 新網域（非官方電商）' };
  }

  if (p0Hit) {
    checks.push(`🔴 P0 語意判斷命中：[${p0Hit.code}] ${p0Hit.desc}`);
    triggered.push(p0Hit.code);

    res.locals.trustintLevel = 5;
    const p0Response = {
      status: 'ok',
      report: buildReport(clean, checks, 1, 0, 0, 0, 0, 0, 0, `🔴 [${p0Hit.code}] ${p0Hit.desc}，強烈建議立即離開`),
      newLevel: 5, newLabel: '多項安全指標異常',
      should_block: true, risk_score: 0.99,
      triggered_rules: triggered
    };
    // P3-06：resolve dedup
    if (resolveDedup) resolveDedup(p0Response);
    clearTimeout(dedupCleanup);
    pendingDeepAnalyze.delete(clean);
    setCachedResult(clean, 5, '多項安全指標異常', 0.99);
    return res.json(p0Response);
  }

  // ══════════════════════════════════════
  // P1：Hard Rules 檢查（A群已在 /v1/check 處理）
  // ══════════════════════════════════════

  // ── BHR1：視覺偽裝 ──
  if (triggered.includes('BHR1_VISUAL_SPOOF')) {
    // 已在 URLScan 處理中觸發
  }

  // ── BHR2：登入盜取 ──
  if (factors.domainAgeDays !== null && factors.domainAgeDays < 14 &&
      factors.certType === 'DV' && factors.hasPasswordField) {
    checks.push('🔴 BHR2：新網域 + DV 憑證 + 登入表單（登入盜取特徵）');
    triggered.push('BHR2_LOGIN_STEAL');
    factors.hasBHR = true;
  }

  // ── BHR5：表單外連 ──
  if (factors.formActionExternal && !SSO_WHITELIST.includes(clean)) {
    checks.push('🔴 BHR5：登入表單資料送往外部網域');
    triggered.push('BHR5_FORM_EXTERNAL');
    factors.hasBHR = true;
  }

  // ── BHR7：事件誘導釣魚（v2.2：加入個資欄位必要條件）──
  const eventKeywords = ['delivery','verify','suspend','tax','package','tracking'];
  const hasEventKeyword = eventKeywords.some(k => clean.includes(k) || urlPath.toLowerCase().includes(k));
  if (hasEventKeyword && factors.domainAgeDays !== null && factors.domainAgeDays < 30) {
    if (factors.hasPasswordField) {
      // 有個資欄位 → L5
      checks.push('🔴 BHR7：事件誘導釣魚（含個資欄位）');
      triggered.push('BHR7_EVENT_PHISHING_L5');
      factors.hasBHR = true;
    } else {
      // 無個資欄位 → 僅 L4（v2.2 降級）
      checks.push('⚠️ BHR7：事件誘導語意 + 新網域（無個資欄位，設 L4）');
      triggered.push('BHR7_EVENT_PHISHING_L4');
    }
  }

  // ── BHR9：合法平台濫用（v2.3.1：擴充觸發條件，ATK-9 防禦）──
  // 從「login/payment 語意」擴展為「任何詐騙語意分析命中」
  if (isParasitePlatform(clean)) {
    const parasiteRiskCategories = ['phishing', 'invest', 'brush', 'fake_shop', 'lure', 
                                     'gov_fake', 'refund', 'escort', 'romance', 'game_scam'];
    const hitCategories = parasiteRiskCategories.filter(cat => semCats.includes(cat));
    if (hitCategories.length > 0) {
      checks.push(`🔴 BHR9：合法平台濫用（偵測到詐騙語意：${hitCategories.join(', ')}）`);
      triggered.push('BHR9_PARASITE_ABUSE');
      factors.hasBHR = true;
    }
  }

  // ── BHR17：寄生平台社交誘導（v2.3.1 新增，ATK-9 防禦）──
  // 寄生平台 + 社交誘導語意（加 LINE/WhatsApp/Telegram）→ L4
  if (isParasitePlatform(clean) && semCats.includes('social') && 
      !triggered.includes('BHR9_PARASITE_ABUSE')) {
    checks.push('🔴 BHR17：寄生平台社交誘導（導流至 LINE/WhatsApp/Telegram）');
    triggered.push('BHR17_PARASITE_SOCIAL');
    factors.hasBHR = true;
  }

  // ── BHR11：投資詐騙（v2.1 已加白名單例外）──
  if (semCats.includes('invest') &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90 &&
      !isLegitFinancial) {
    checks.push('🔴 BHR11：投資詐騙語意 + 新網域（非合法金融機構）');
    triggered.push('BHR11_INVEST_SCAM');
    factors.hasBHR = true;
  }

  // ── BHR12：刷單詐騙（v2.1 已加儲值條件）──
  if (semCats.includes('brush') &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90) {
    checks.push('🔴 BHR12：刷單詐騙語意 + 新網域');
    triggered.push('BHR12_BRUSH_SCAM');
    factors.hasBHR = true;
  }

  // ── BHR13：非官方 APP / 假更新（v2.2 擴充）──
  const fakeUpdateKeywords = ['browser update','系統更新','chrome update','flash update','需要更新'];
  const hasFakeUpdate = fakeUpdateKeywords.some(k => (factors.pageTitle || '').toLowerCase().includes(k));
  if (hasFakeUpdate && !['apple.com','google.com','microsoft.com'].includes(clean)) {
    checks.push('🔴 BHR13：偵測到偽裝系統/瀏覽器更新提示');
    triggered.push('BHR13_FAKE_UPDATE');
    factors.hasBHR = true;
    factors.hasFakeUpdateUI = true;
  }

  // ── BHR14：假客服/假退款（v2.2 新增）──
  if (factors.hasRefundKeywords &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90 &&
      !isLegitFinancial) {
    checks.push('🔴 BHR14：假客服/假退款語意 + 新網域');
    triggered.push('BHR14_FAKE_REFUND');
    factors.hasBHR = true;
  }

  // ── BHR15：社交誘導離站（v2.2 新增）──
  if (factors.hasSocialLure &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90 &&
      (semCats.includes('invest') || semCats.includes('social'))) {
    checks.push('🔴 BHR15：社交誘導離站（導流至 LINE/WhatsApp + 投資/交友語意）');
    triggered.push('BHR15_SOCIAL_LURE');
    factors.hasBHR = true;
  }

  // ── BHR16：OAuth 授權劫持（v2.2 新增）──
  // 注意：完整偵測需要 V2 爬蟲支援，目前只做基礎 URL 特徵
  if (urlPath.includes('oauth') || urlPath.includes('callback') || urlPath.includes('authorize')) {
    if (factors.domainAgeDays !== null && factors.domainAgeDays < 90 && !isLegitFinancial) {
      checks.push('⚠️ BHR16：URL 含 OAuth 授權相關路徑 + 新網域');
      triggered.push('BHR16_OAUTH_HIJACK');
      factors.hasBHR = true;
    }
  }

  // ── BHR18：假客服浮動按鈕（v3.0 新增）──
  // 頁面有 WhatsApp/LINE 浮動按鈕 + 新域名 → 一頁式詐騙標配
  if (dom_scan && dom_scan.hasSocialLure &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90 &&
      factors.isOnePage && !isLegitFinancial) {
    checks.push('🔴 BHR18：假客服浮動按鈕（一頁式 + 社交誘導 + 新網域）');
    triggered.push('BHR18_FAKE_CS_FLOAT');
    factors.hasBHR = true;
  }

  // ── BHR19：假付款頁面（v3.0 新增）──
  // URL 含 pay/checkout/order + 非知名電商 + 新域名
  if ((urlPath.includes('pay') || urlPath.includes('checkout') || urlPath.includes('order') ||
       urlPath.includes('payment') || urlPath.includes('billing')) &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90 &&
      !KNOWN_SAFE.has(clean) && !isLegitFinancial &&
      !majesticList.has(clean)) {
    checks.push('🔴 BHR19：假付款頁面（付款路徑 + 非知名網站 + 新網域）');
    triggered.push('BHR19_FAKE_PAYMENT');
    factors.hasBHR = true;
  }

  // ── BHR20：假抽獎/中獎頁面（v3.0 新增）──
  // 頁面含「恭喜」+「中獎」+「領取」等語意 + 新域名
  {
    const bodyText = (factors.pageTitle || '').toLowerCase() + ' ' + (factors.semanticText || '').toLowerCase();
    const prizeKeywords = ['恭喜', '中獎', '領取', '獎品', '幸運', '抽獎結果', '得獎'];
    const prizeCount = prizeKeywords.filter(k => bodyText.includes(k)).length;
    if (prizeCount >= 2 && factors.domainAgeDays !== null && factors.domainAgeDays < 180 &&
        !KNOWN_SAFE.has(clean) && !majesticList.has(clean)) {
      checks.push('🔴 BHR20：假抽獎/中獎頁面（中獎語意 + 非知名網站）');
      triggered.push('BHR20_FAKE_PRIZE');
      factors.hasBHR = true;
    }
  }

  // ── BHR-OV：OV/EV 憑證主體不符（v2.4 新增，V1-09）──
  // 檢查聲稱是某品牌但憑證組織不匹配
  const bhrOvResult = checkBHROV(clean, factors.certOrg, factors.certType, factors.pageTitle);
  if (bhrOvResult && bhrOvResult.triggered) {
    checks.push(`🔴 ${bhrOvResult.code}：${bhrOvResult.desc}`);
    triggered.push('BHR_OV_CERT_MISMATCH');
    factors.hasBHR = true;
    factors.hasCriticalSignal = true;  // 這是高信心規則
  }

  // ══════════════════════════════════════
  // P5：分群機率模型
  // ══════════════════════════════════════
  const { risk, r1, r2, r3, r4, r5, r6 } = calcSoftRisk(factors);

  // ══════════════════════════════════════
  // P2/P3：Critical Clusters 判斷
  // ══════════════════════════════════════
  let clusterHit = null;

  // ── P2：Confidence ≥ 0.90 → L5 ──

  // CC1：名牌仿冒陷阱
  if (!clusterHit && triggered.includes('BRAND_SPOOF_CONFIRMED') && factors.hasFishingKeyword) {
    clusterHit = { level: 5, code: 'CC1', desc: '名牌仿冒陷阱（品牌仿冒 + 釣魚關鍵字）', confidence: 0.92 };
    factors.hasCriticalCluster = true;
  }

  // CC2：拋棄式釣魚台
  if (!clusterHit && factors.domainAgeDays !== null && factors.domainAgeDays < 14 &&
      factors.whoisHidden && factors.certType === 'DV') {
    clusterHit = { level: 5, code: 'CC2', desc: '拋棄式釣魚台（極新網域 + WHOIS隱藏 + DV憑證）', confidence: 0.90 };
    factors.hasCriticalCluster = true;
  }

  // CC3：惡意基礎設施（v2.2：ASN 層級）
  if (!clusterHit && factors.abuseScore >= 75 && factors.asnTier === 'bulletproof') {
    clusterHit = { level: 5, code: 'CC3', desc: '惡意基礎設施（Bulletproof ASN + 高風險IP）', confidence: 0.91 };
    factors.hasCriticalCluster = true;
  }
  if (!clusterHit && factors.abuseScore >= 75 && triggered.includes('CC10_EVIL_NEIGHBOR')) {
    clusterHit = { level: 5, code: 'CC3', desc: '惡意基礎設施（高風險IP + 惡意鄰居）', confidence: 0.91 };
    factors.hasCriticalCluster = true;
  }

  // CC11：廣告釣魚鏈
  if (!clusterHit && factors.hasAdTraffic && factors.redirectCount >= 3 &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 30) {
    clusterHit = { level: 5, code: 'CC11', desc: '廣告釣魚鏈（廣告 + 多層跳轉 + 新網域）', confidence: 0.90 };
    factors.hasCriticalCluster = true;
  }

  // CC12：導流跳轉詐騙
  if (!clusterHit && factors.redirectCount >= 3 && semCats.includes('phishing')) {
    clusterHit = { level: 5, code: 'CC12', desc: '導流跳轉詐騙（3+跳轉 + 金融意圖）', confidence: 0.90 };
    factors.hasCriticalCluster = true;
  }

  // CC14：Punycode 同形字攻擊
  if (!clusterHit && clean.includes('xn--') && spoofResult) {
    clusterHit = { level: 5, code: 'CC14', desc: `Punycode 同形字攻擊（仿冒 ${spoofResult.brand}）`, confidence: 0.93 };
    factors.hasCriticalCluster = true;
  }

  // CC16：封閉式投資平台
  if (!clusterHit && factors.isOnePage && semCats.includes('invest') &&
      !isLegitFinancial) {
    clusterHit = { level: 5, code: 'CC16', desc: '封閉式投資平台（僅登入頁 + 投資語意）', confidence: 0.91 };
    factors.hasCriticalCluster = true;
  }

  // CC17：假官署組合（v2.1 已加金流欄位）
  if (!clusterHit && semCats.includes('gov_fake') &&
      !clean.endsWith('.gov.tw') && !clean.endsWith('.com.tw') &&
      semCats.includes('phishing')) {
    clusterHit = { level: 5, code: 'CC17', desc: '假官署組合（政府/民生語意 + 非官方域名 + 金流）', confidence: 0.90 };
    factors.hasCriticalCluster = true;
  }

  // CC18：中獎+信用卡
  if (!clusterHit && semCats.includes('lure') && semCats.includes('phishing') &&
      !isLegitFinancial) {
    clusterHit = { level: 5, code: 'CC18', desc: '中獎語意 + 金流意圖（非官方電商）', confidence: 0.91 };
    factors.hasCriticalCluster = true;
  }

  // CC19：一頁式詐騙電商（v2.2 新增）
  if (!clusterHit && factors.isOnePage && factors.hasAdTraffic &&
      (semCats.includes('fake_shop') || factors.hasCODPayment) &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 180) {
    clusterHit = { level: 5, code: 'CC19', desc: '一頁式詐騙電商（單頁 + 廣告 + 貨到付款/假電商語意）', confidence: 0.90 };
    factors.hasCriticalCluster = true;
  }

  // CC20：Clipboard 劫持（v2.2 新增）
  if (!clusterHit && triggered.includes('CC20_CLIPBOARD_HIJACK')) {
    clusterHit = { level: 5, code: 'CC20', desc: 'Clipboard 劫持（clipboard API + 加密貨幣語意）', confidence: 0.91 };
    factors.hasCriticalCluster = true;
  }

  // CC21：假系統更新（v2.2 新增）
  if (!clusterHit && factors.hasFakeUpdateUI &&
      !['apple.com','google.com','microsoft.com'].includes(clean)) {
    clusterHit = { level: 5, code: 'CC21', desc: '假系統更新（偽裝更新通知 + 非官方域名）', confidence: 0.92 };
    factors.hasCriticalCluster = true;
  }

  // CC22：廣告導流 + 高風險 TLD + 新網域（v3.0 新增）
  // 針對 TikTok/Facebook 廣告導流到 .shop/.site/.top 等一頁式詐騙站
  if (!clusterHit && factors.hasAdTraffic &&
      tld && TLD_TIER2_STRONG.has(tld) &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90) {
    clusterHit = { level: 4, code: 'CC22', desc: '廣告導流詐騙站（廣告流量 + 高風險 TLD + 新網域）', confidence: 0.82 };
    factors.hasCriticalCluster = true;
  }

  // CC23：社交誘導 + 投資關鍵字 + 新網域（v3.0 新增）
  // 殺豬盤標準模式：加 LINE → 帶你賺錢 → 投資平台
  if (!clusterHit && factors.hasSocialLure && semCats.includes('invest') &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90 &&
      !isLegitFinancial) {
    clusterHit = { level: 5, code: 'CC23', desc: '殺豬盤組合（社交誘導 + 投資語意 + 新網域）', confidence: 0.91 };
    factors.hasCriticalCluster = true;
  }

  // IPQS 確認
  if (!clusterHit && (triggered.includes('IPQS_HIGH') && factors.ipqsPhishing)) {
    clusterHit = { level: 5, code: 'CC_IPQS', desc: 'IPQualityScore 確認釣魚網站', confidence: 0.92 };
    factors.hasCriticalCluster = true;
  }

  // URLScan 惡意 + 品牌仿冒
  if (!clusterHit && factors.pageMalicious && triggered.includes('BRAND_SPOOF_CONFIRMED')) {
    clusterHit = { level: 5, code: 'CC_URLSCAN', desc: 'URLScan 確認品牌仿冒惡意頁面', confidence: 0.93 };
    factors.hasCriticalCluster = true;
  }

  // v2.3 修正：VT_HIGH（5+ 引擎惡意）→ 直接 L5
  if (!clusterHit && triggered.includes('VT_HIGH')) {
    clusterHit = { level: 5, code: 'A4_VT', desc: '多個國際資安引擎標記為惡意網域', confidence: 0.95 };
    factors.hasCriticalCluster = true;
  }

  // v2.3 修正：IPQS_HIGH（90+ 或 phishing/malware）→ 直接 L4（搭配其他信號可升 L5）
  if (!clusterHit && triggered.includes('IPQS_HIGH')) {
    const ipqsLevel = (triggered.includes('VT_MID') || factors.hasCriticalSignal) ? 5 : 4;
    clusterHit = { level: ipqsLevel, code: 'A6_IPQS', desc: '國際資安資料庫標記為極高風險', confidence: 0.90 };
    factors.hasCriticalCluster = true;
  }

  // BHR → L5
  if (!clusterHit && triggered.includes('BHR2_LOGIN_STEAL'))
    clusterHit = { level: 5, code: 'BHR2', desc: '登入盜取特徵（新網域 + 登入表單 + DV憑證）' };
  if (!clusterHit && triggered.includes('BHR5_FORM_EXTERNAL'))
    clusterHit = { level: 5, code: 'BHR5', desc: '表單資料外連至非官方網域' };
  if (!clusterHit && triggered.includes('BHR6_CLICKJACK'))
    clusterHit = { level: 5, code: 'BHR6', desc: '點擊劫持：iframe 嵌入官方機構頁面' };
  if (!clusterHit && triggered.includes('BHR1_VISUAL_SPOOF'))
    clusterHit = { level: 5, code: 'BHR1', desc: '視覺偽裝：頁面聲稱是品牌官網' };
  if (!clusterHit && triggered.includes('MALICIOUS_SCRIPT'))
    clusterHit = { level: 5, code: 'BHR_SCRIPT', desc: '偵測到鍵盤側錄或竊取腳本' };
  if (!clusterHit && triggered.includes('BHR7_EVENT_PHISHING_L5'))
    clusterHit = { level: 5, code: 'BHR7', desc: '事件誘導釣魚（含個資欄位）' };
  if (!clusterHit && triggered.includes('BHR9_PARASITE_ABUSE'))
    clusterHit = { level: 5, code: 'BHR9', desc: '合法平台濫用（偵測到詐騙語意）' };
  if (!clusterHit && triggered.includes('BHR11_INVEST_SCAM'))
    clusterHit = { level: 5, code: 'BHR11', desc: '投資詐騙（語意 + 新網域）' };
  if (!clusterHit && triggered.includes('BHR12_BRUSH_SCAM'))
    clusterHit = { level: 5, code: 'BHR12', desc: '刷單詐騙（語意 + 新網域）' };
  if (!clusterHit && triggered.includes('BHR13_FAKE_UPDATE'))
    clusterHit = { level: 5, code: 'BHR13', desc: '偽裝系統/瀏覽器更新' };
  if (!clusterHit && triggered.includes('BHR14_FAKE_REFUND'))
    clusterHit = { level: 5, code: 'BHR14', desc: '假客服/假退款（語意 + 新網域）' };
  if (!clusterHit && triggered.includes('BHR15_SOCIAL_LURE'))
    clusterHit = { level: 5, code: 'BHR15', desc: '社交誘導離站（導流至私訊工具）' };
  if (!clusterHit && triggered.includes('BHR16_OAUTH_HIJACK'))
    clusterHit = { level: 5, code: 'BHR16', desc: 'OAuth 授權劫持（新網域 + 授權路徑）' };
  // v2.3.1 新增：BHR17 寄生平台社交誘導 → L4（比 BHR9 輕）
  if (!clusterHit && triggered.includes('BHR17_PARASITE_SOCIAL'))
    clusterHit = { level: 4, code: 'BHR17', desc: '寄生平台社交誘導（導流至私訊工具）', confidence: 0.75 };
  // v3.0 新增：BHR18 假客服浮動按鈕 → L4
  if (!clusterHit && triggered.includes('BHR18_FAKE_CS_FLOAT'))
    clusterHit = { level: 4, code: 'BHR18', desc: '假客服浮動按鈕（一頁式 + 社交誘導 DOM + 新網域）', confidence: 0.78 };
  // v3.0 新增：BHR19 假付款頁面 → L4
  if (!clusterHit && triggered.includes('BHR19_FAKE_PAYMENT'))
    clusterHit = { level: 4, code: 'BHR19', desc: '假付款頁面（付款路徑 + 非知名網站 + 新網域）', confidence: 0.77 };
  // v3.0 新增：BHR20 假抽獎/中獎 → L4
  if (!clusterHit && triggered.includes('BHR20_FAKE_PRIZE'))
    clusterHit = { level: 4, code: 'BHR20', desc: '假抽獎/中獎頁面（中獎語意 ≥2 + 非知名 + 新網域）', confidence: 0.78 };

  // ══════════════════════════════════════
  // v2.3.1：DOM-Lite 觸發規則（ATK-1 防禦）
  // ══════════════════════════════════════
  // DOM-BHR-1：新網域 + 信用卡欄位 → L5（極高風險）
  if (!clusterHit && triggered.includes('DOM_CREDIT_CARD') &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90) {
    clusterHit = { level: 5, code: 'DOM_CC', desc: 'DOM 偵測：新網域 + 信用卡輸入欄位', confidence: 0.92 };
    factors.hasCriticalCluster = true;
  }
  // DOM-BHR-2：投資關鍵字 + 社交誘導 → L5（殺豬盤特徵）
  if (!clusterHit && triggered.includes('DOM_INVEST_SOCIAL')) {
    clusterHit = { level: 5, code: 'DOM_PIG', desc: 'DOM 偵測：投資關鍵字 + 社交誘導（殺豬盤特徵）', confidence: 0.90 };
    factors.hasCriticalCluster = true;
  }
  // DOM-BHR-3：假電商 + 倒數計時 → L4（一頁式詐騙）
  if (!clusterHit && triggered.includes('DOM_FAKE_SHOP_COUNTDOWN')) {
    clusterHit = { level: 4, code: 'DOM_SHOP', desc: 'DOM 偵測：假電商特徵 + 倒數計時器（一頁式詐騙）', confidence: 0.82 };
    factors.hasCriticalCluster = true;
  }
  // DOM-BHR-4：品牌提及 + 非官方域名 → L4
  if (!clusterHit && triggered.includes('DOM_BRAND_MENTION_UNOFFICIAL')) {
    clusterHit = { level: 4, code: 'DOM_BRAND', desc: 'DOM 偵測：頁面聲稱是品牌官網，但非官方域名', confidence: 0.78 };
    factors.hasCriticalCluster = true;
  }
  // DOM-BHR-5：表單外連 + 新網域 → L5
  if (!clusterHit && triggered.includes('DOM_CREDIT_CARD') && 
      factors.formActionExternal && factors.domScanFormActions.length > 0) {
    clusterHit = { level: 5, code: 'DOM_FORM_EXT', desc: 'DOM 偵測：信用卡資料送往外部網域', confidence: 0.95 };
    factors.hasCriticalCluster = true;
  }
  // v3.0 BHR-IMG：低文字 + 高圖片 + 新網域 → L4
  if (!clusterHit && triggered.includes('BHR_IMG_LOW_TEXT') &&
      factors.domainAgeDays !== null && factors.domainAgeDays < 90) {
    clusterHit = { level: 4, code: 'BHR_IMG', desc: 'DOM 偵測：圖片化詐騙特徵（低文字+高圖片+新網域）', confidence: 0.72 };
    factors.hasCriticalCluster = true;
  }

  // ── P3：Confidence 0.70–0.89 → L4 地板 ──
  if (!clusterHit) {
    // CC4：超典型詐騙
    if (factors.domainAgeDays !== null && factors.domainAgeDays < 30 &&
        factors.whoisHidden && factors.hasFishingKeyword) {
      clusterHit = { level: 4, code: 'CC4', desc: '超典型詐騙特徵（新網域 + WHOIS隱藏 + 釣魚關鍵字）', confidence: 0.85 };
      factors.hasCriticalCluster = true;
    }
    // CC5：隱藏跳板（v2.2：ASN 層級）
    else if (factors.redirectCount >= 3 && factors.hasMetaRedirect &&
             (factors.asnTier === 'bulletproof' || factors.asnTier === 'high_abuse')) {
      clusterHit = { level: 4, code: 'CC5', desc: '隱藏跳板組合（多層跳轉 + 高風險ASN）', confidence: 0.75 };
      factors.hasCriticalCluster = true;
    }
    // CC6：金融偽裝
    else if (factors.hasFishingKeyword && factors.certType === 'DV' && factors.whoisHidden) {
      clusterHit = { level: 4, code: 'CC6', desc: '金融偽裝組合（釣魚關鍵字 + DV憑證 + WHOIS隱藏）', confidence: 0.78 };
      factors.hasCriticalCluster = true;
    }
    // CC7：釣魚登入
    else if (factors.isDGA && factors.hasPasswordField) {
      clusterHit = { level: 4, code: 'CC7', desc: '釣魚登入組合（DGA亂碼域名 + 登入表單）', confidence: 0.80 };
      factors.hasCriticalCluster = true;
    }
    // CC8：SSL 偽裝（v2.2：加入第四條件）
    else if (factors.certType === 'DV' && factors.certAgeDays !== null &&
             factors.certAgeDays < 30 && factors.domainAgeDays !== null && factors.domainAgeDays < 90 &&
             (factors.whoisHidden || factors.hasFishingKeyword)) {  // v2.2：新增條件④
      clusterHit = { level: 4, code: 'CC8', desc: 'SSL 偽裝組合（新DV + 新網域 + WHOIS隱藏或釣魚關鍵字）', confidence: 0.72 };
      factors.hasCriticalCluster = true;
    }
    // CC9：跳轉詐騙
    else if (triggered.includes('REDIRECT_CHAIN_HIGH') &&
             factors.domainAgeDays !== null && factors.domainAgeDays < 30) {
      clusterHit = { level: 4, code: 'CC9', desc: '跳轉詐騙組合（多層跳轉 + 新網域）', confidence: 0.73 };
      factors.hasCriticalCluster = true;
    }
    // CC10：惡意鄰居
    else if (triggered.includes('CC10_EVIL_NEIGHBOR') && risk > 0.3) {
      clusterHit = { level: 4, code: 'CC10', desc: '惡意鄰居：與 165 黑名單 IP 同網段', confidence: 0.76 };
      factors.hasCriticalCluster = true;
    }
    // CC13：AiTM 反向代理
    else if (triggered.includes('URLSCAN_MALICIOUS') && factors.hasFishingKeyword) {
      clusterHit = { level: 4, code: 'CC13', desc: 'URLScan 可疑 + 釣魚關鍵字', confidence: 0.88 };
      factors.hasCriticalCluster = true;
    }
    // BHR7 L4 版（無個資欄位）
    else if (triggered.includes('BHR7_EVENT_PHISHING_L4')) {
      clusterHit = { level: 4, code: 'BHR7', desc: '事件誘導語意 + 新網域（無個資欄位）' };
    }
    // 寄生攻擊
    else if (triggered.includes('PARASITE_ATTACK') && !triggered.includes('BHR9_PARASITE_ABUSE')) {
      clusterHit = { level: 4, code: 'PARASITE', desc: '寄生攻擊：高信譽平台用戶內容頁' };
    }
    // IPQS 中高風險
    else if (triggered.includes('IPQS_MID')) {
      clusterHit = { level: 4, code: 'IPQS_MID', desc: `IPQualityScore 高風險（${factors.ipqsScore}分）` };
    }
    // v2.3 修正：VT_MID（3-4 引擎惡意）→ L4
    else if (triggered.includes('VT_MID')) {
      clusterHit = { level: 4, code: 'VT_MID', desc: '多個國際資安引擎標記為可疑', confidence: 0.80 };
      factors.hasCriticalCluster = true;
    }
    // TLD Tier 1 地板
    else if (TLD_TIER1_DIRECT_L4.has(tld)) {
      clusterHit = { level: 4, code: 'TLD_T1', desc: `免費高濫用 TLD（${tld}）直接 L4` };
    }
    // v2.3 新增：TLD Tier 2 + 廣告導流 → L4（.shop/.xyz/.top 等 + TikTok/FB 廣告）
    else if (TLD_TIER2_STRONG.has(tld) && factors.hasAdTraffic) {
      clusterHit = { level: 4, code: 'TLD_AD', desc: `高濫用 TLD（${tld}）+ 社群廣告導流`, confidence: 0.75 };
    }
    // v2.3 新增：TLD Tier 2 + 網域年齡不明或 < 90 天 → L4
    else if (TLD_TIER2_STRONG.has(tld) && (factors.domainAgeDays === null || factors.domainAgeDays < 90)) {
      clusterHit = { level: 4, code: 'TLD_NEW', desc: `高濫用 TLD（${tld}）+ 新網域或年齡不明`, confidence: 0.70 };
    }
    // v3.0 修正：品牌仿冒單獨確認 → 至少 L4
    // P1 的 BRAND_SPOOF 在 /v1/check 中直接回傳 L4，
    // 但 deep-analyze 的 P5 risk score 可能不夠高導致降回 L3。
    // 這違反「強訊號 > 弱訊號堆疊」原則：品牌仿冒是強訊號，不該被 P5 覆蓋。
    else if (triggered.includes('BRAND_SPOOF_CONFIRMED')) {
      clusterHit = { level: 4, code: 'BRAND_SPOOF', desc: `疑似仿冒 ${spoofResult?.brand || '品牌'} 官方網域`, confidence: 0.85 };
      factors.hasCriticalCluster = true;
    }
  }

  // ══════════════════════════════════════
  // V2.5：爬蟲 P0 語意分析（對 L3 邊界案例）
  // ══════════════════════════════════════
  let crawlerP0 = null;
  
  // 條件：沒有 clusterHit、風險分數在 L3 區間、有爬蟲模組
  // v3.0：移除 BROWSERLESS_API_KEY 依賴，改用 CRAWLER_URL
  // P2-01：前端 DOM 掃描失敗（dom_scan 為 null）時也強制爬蟲，避免偽造/失敗導致防護盲區
  const domScanMissing = !dom_scan && !isKnownSafeDomain;
  const shouldCrawl = crawler && process.env.CRAWLER_URL && (
    (!clusterHit && risk >= 0.20 && risk < 0.80) ||  // 原有條件：L3 邊界案例
    domScanMissing  // P2-01：前端掃描缺失，需要伺服器端獨立驗證
  );
  
  if (shouldCrawl) {
    try {
      const crawlReason = domScanMissing ? 'dom_scan_missing' : `risk=${(risk*100).toFixed(1)}%`;
      console.log(`[CRAWLER] 觸發爬蟲分析：${clean} (${crawlReason})`);
      if (domScanMissing) triggered.push('DOM_SCAN_MISSING');
      const crawlResult = await crawler.crawlAndAnalyze(clean);
      
      if (crawlResult.success && crawlResult.p0.triggered) {
        crawlerP0 = crawlResult.p0;
        console.log(`[CRAWLER] P0 命中：${clean} | ${crawlerP0.rules.map(r => r.code).join(', ')}`);
        
        if (crawlerP0.recommendedLevel === 5) {
          clusterHit = {
            level: 5,
            code: crawlerP0.rules[0]?.code || 'P0-CONTENT',
            desc: `頁面內容分析：${crawlerP0.rules.map(r => r.category).join('、')}`,
            confidence: crawlerP0.rules[0]?.confidence || 0.85,
          };
          factors.hasCriticalCluster = true;
        } else if (crawlerP0.recommendedLevel === 4) {
          clusterHit = {
            level: 4,
            code: crawlerP0.rules[0]?.code || 'P0-SUSPICIOUS',
            desc: `頁面內容可疑：${crawlerP0.rules.map(r => r.category).join('、')}`,
            confidence: crawlerP0.rules[0]?.confidence || 0.75,
          };
        }
        
        crawlerP0.rules.forEach(r => triggered.push(r.code));
      }

      // V2-01：視覺相似度比對（如果 P0 沒觸發，用截圖比對品牌仿冒）
      if (!clusterHit && crawler.visualMatch) {
        try {
          const vmResult = await crawler.visualMatch(clean);
          if (vmResult.match && vmResult.match.similarity >= 75) {
            console.log(`[V2-01] 視覺仿冒偵測：${clean} 疑似仿冒 ${vmResult.match.brand}（${vmResult.match.similarity}%）`);
            clusterHit = {
              level: vmResult.match.similarity >= 85 ? 5 : 4,
              code: 'V2-01-VISUAL',
              desc: `視覺相似度偵測：頁面外觀疑似仿冒「${vmResult.match.brand}」（${vmResult.match.similarity}% 相似）`,
              confidence: vmResult.match.similarity / 100,
            };
            triggered.push('VISUAL_MATCH_' + vmResult.match.brand.toUpperCase());
            if (vmResult.match.similarity >= 85) factors.hasCriticalCluster = true;
          }
        } catch (vmErr) {
          console.log(`[V2-01] 視覺比對失敗：${vmErr.message}`);
        }
      }
      
      // 儲存爬蟲結果到 DB（非阻塞）
      if (crawlResult.success) {
        getOrCreateDomainId(clean).then(domainId => {
          if (domainId) {
            pool.query(`
              INSERT INTO crawl_results (domain_id, page_title, p0_triggered, crawl_duration_ms)
              VALUES ($1, $2, $3, $4)
            `, [
              domainId,
              crawlResult.crawl?.title?.slice(0, 255) || '',
              crawlerP0?.rules?.map(r => r.code) || [],
              crawlResult.crawl?.duration_ms || 0
            ]).catch(e => console.error('爬蟲結果儲存失敗:', e.message));
          }
        });
      }
    } catch (crawlErr) {
      console.error(`[CRAWLER] 錯誤：${clean} | ${crawlErr.message}`);
    }
  }

  // ══════════════════════════════════════
  // v3.0：爬蟲頁面品質弱訊號補強（不直接升級，但調高 risk）
  // ══════════════════════════════════════
  if (crawlerP0 && crawlerP0.legalPages) {
    const lp = crawlerP0.legalPages;
    const noLegal = !lp.hasPrivacyPage && !lp.hasTermsPage;
    const pq = crawlerP0.pageQuality || {};
    const th = crawlerP0.threats || {};

    // v3.0：設定信任因子供 calcSoftRisk 負向減分使用
    factors.hasLegalPages = lp.hasPrivacyPage && lp.hasTermsPage;
    const compInfo = crawlerP0.companyInfo || {};
    factors.hasCompanyInfo = compInfo.hasCompanyName && (compInfo.hasPhoneNumber || compInfo.hasPhysicalAddress);

    // 無法律條款 + 非知名站 → risk 加 0.05
    if (noLegal && !KNOWN_SAFE.has(clean) && !majesticList.has(clean)) {
      risk = Math.min(risk + 0.05, 1);
      triggered.push('NO_LEGAL_PAGES');
    }

    // 無 HTTPS → risk 加 0.08
    if (th.isHttps === false) {
      risk = Math.min(risk + 0.08, 1);
      triggered.push('NO_HTTPS');
    }

    // 假警告/假病毒 → 直接升 L4
    if (th.hasFakeAlert || th.hasDownloadPrompt) {
      if (!clusterHit) {
        clusterHit = { level: 4, code: 'FAKE_ALERT', desc: '頁面含有假病毒/假下載警告' };
        triggered.push('FAKE_ALERT');
      }
    }

    // 無 favicon + 無法律條款 + 文字少 → risk 加 0.06
    if (!pq.hasFavicon && noLegal && (crawlerP0.dom?.visibleTextLength || 0) < 300) {
      risk = Math.min(risk + 0.06, 1);
      triggered.push('LOW_QUALITY_PAGE');
    }

    // v3.0：公司資訊 + 敏感資料偵測
    const ci = crawlerP0.companyInfo || {};
    const sd = crawlerP0.sensitiveDataRequest || {};
    const noCompany = !ci.hasCompanyName && !ci.hasPhoneNumber && !ci.hasPhysicalAddress;

    // 要求敏感資料 + 無公司資訊 → 直接 L4
    if (sd.hasSensitiveDataRequest && noCompany && !clusterHit) {
      clusterHit = {
        level: sd.totalSensitiveFields >= 3 ? 5 : 4,
        code: 'SENSITIVE_NO_COMPANY',
        desc: `要求敏感資料（${sd.totalSensitiveFields} 個欄位）但無公司資訊、無客服電話`,
      };
      triggered.push('SENSITIVE_NO_COMPANY');
      if (sd.totalSensitiveFields >= 3) factors.hasCriticalCluster = true;
    }

    // 單獨無公司資訊 + 無法律條款 → risk 加 0.07
    if (noCompany && noLegal && !KNOWN_SAFE.has(clean) && !majesticList.has(clean)) {
      risk = Math.min(risk + 0.07, 1);
      triggered.push('NO_IDENTITY');
    }

    // 跨域轉址 → risk 加 0.10
    if (crawlerP0.redirectInfo && crawlerP0.redirectInfo.crossDomain) {
      risk = Math.min(risk + 0.10, 1);
      triggered.push('CROSS_DOMAIN_REDIRECT');
    }

    // v3.0：付款頁面偵測（非白名單）
    const pay = crawlerP0.paymentDetection || {};
    const plat = crawlerP0.platformDetection || {};

    // 非白名單站有付款頁面 + 無合法第三方支付 → 直接 L4
    if (pay.hasPaymentPage && !pay.hasLegitPayment && !KNOWN_SAFE.has(clean) && !clusterHit) {
      clusterHit = {
        level: 4,
        code: 'UNSAFE_PAYMENT',
        desc: '此網站有付款功能但未使用知名第三方支付平台，請勿輸入信用卡資訊',
      };
      triggered.push('UNSAFE_PAYMENT');
    }

    // 非白名單站有付款 + 有合法支付 → 警告但不升級
    if (pay.hasPaymentPage && pay.hasLegitPayment && !KNOWN_SAFE.has(clean) && !majesticList.has(clean)) {
      risk = Math.min(risk + 0.05, 1);
      triggered.push('PAYMENT_DETECTED');
    }

    // 不知名虛擬貨幣平台 → L4
    if (plat.hasCryptoFeature && !KNOWN_SAFE.has(clean) && !majesticList.has(clean) && !clusterHit) {
      clusterHit = {
        level: 4,
        code: 'UNKNOWN_CRYPTO',
        desc: '此網站具有虛擬貨幣交易平台特徵，但非已知合法交易所，請特別小心',
      };
      triggered.push('UNKNOWN_CRYPTO');
    }

    // 不知名投資平台 → L4
    if (plat.hasInvestmentFeature && !KNOWN_SAFE.has(clean) && !majesticList.has(clean) && !clusterHit) {
      clusterHit = {
        level: 4,
        code: 'UNKNOWN_INVESTMENT',
        desc: '此網站具有投資平台特徵，但非已知合法金融機構，請特別小心',
      };
      triggered.push('UNKNOWN_INVESTMENT');
    }

    // 聊天室 + 付款 + 無公司 = 感情詐騙平台 → L5
    if (plat.hasChatFeature && pay.hasPaymentPage && noCompany && !clusterHit) {
      clusterHit = {
        level: 5,
        code: 'ROMANCE_PLATFORM',
        desc: '此網站同時具有聊天室和付款功能且無公司資訊，高度疑似感情詐騙平台',
      };
      factors.hasCriticalCluster = true;
      triggered.push('ROMANCE_PLATFORM');
    }

    // BHR-21：孤島網頁 + 敏感資料 → L4
    if (crawlerP0.hollowShell?.isHollow && !clusterHit) {
      clusterHit = {
        level: 4,
        code: 'HOLLOW_SHELL',
        desc: '此網站超過半數連結無法點擊，疑似快速搭建的詐騙頁面',
      };
      triggered.push('HOLLOW_SHELL');
    }

    // BHR-22：右鍵禁用 + 金融語意 → risk +0.15
    if (crawlerP0.antiAnalysis?.hasDisableRightClick || crawlerP0.antiAnalysis?.hasDebuggerTrap) {
      risk = Math.min(risk + 0.15, 1);
      triggered.push('ANTI_ANALYSIS');
    }

    // BHR-23：APK/EXE 下載 → 直接 L5
    if (crawlerP0.sideloadLinks?.hasSideload && !clusterHit) {
      clusterHit = {
        level: 5,
        code: 'SIDELOAD',
        desc: '此網站提供不明來源的 APP 安裝檔下載，可能植入惡意程式',
      };
      factors.hasCriticalCluster = true;
      triggered.push('SIDELOAD');
    }

    // BHR-24：私鑰/助記詞索取 → 直接 L5（Kill Switch）
    if (crawlerP0.seedPhraseRequest?.detected && !clusterHit) {
      clusterHit = {
        level: 5,
        code: 'SEED_PHRASE',
        desc: '此網站要求輸入助記詞或私鑰，這是竊取虛擬貨幣的詐騙手法',
      };
      factors.hasCriticalCluster = true;
      triggered.push('SEED_PHRASE');
    }

    // CC-22：廣告導流 + 高風險 TLD + 新域名 = 一頁式廣告詐騙
    if (factors.hasAdTraffic && factors.tld && TLD_TIER2_STRONG.has(factors.tld) &&
        (factors.domainAgeDays === null || factors.domainAgeDays < 30) && !clusterHit) {
      clusterHit = {
        level: 4,
        code: 'AD_TRAFFIC_NEW_SITE',
        desc: '此網站透過社群廣告導流到新註冊的高風險域名，高度疑似一頁式詐騙',
      };
      triggered.push('AD_TRAFFIC_SCAM');
    }

    // CC-23：殺豬盤組合（社交誘導 + 投資語意 + 倒數計時 + 低文字高圖片）
    const semResult = factors.semanticResult || {};
    const hasSocialSem = (semResult.categories || []).includes('social') || (semResult.categories || []).includes('romance');
    const hasInvestSem = (semResult.categories || []).includes('invest');
    if (hasSocialSem && hasInvestSem && !clusterHit) {
      clusterHit = {
        level: 5,
        code: 'PIG_BUTCHERING_COMBO',
        desc: '同時偵測到社交誘導與投資詐騙語意，高度疑似殺豬盤詐騙',
      };
      factors.hasCriticalCluster = true;
      triggered.push('PIG_BUTCHERING_COMBO');
    }
  }

  // ══════════════════════════════════════
  // 最終判定（P5→P6 結果整合）
  // ══════════════════════════════════════
  let newLevel, newLabel, summary;

  if (clusterHit && clusterHit.level === 5) {
    newLevel = 5; newLabel = '多項安全指標異常';
    summary = '🔴 偵測到嚴重風險指標，強烈建議立即離開此網站';
  } else if (clusterHit && clusterHit.level === 4) {
    newLevel = 4; newLabel = '極高風險';
    summary = '⚠️ 偵測到多項可疑特徵，請勿輸入個人資料或進行金流操作';
  } else if (risk >= ENGINE_THRESHOLDS.risk_l4) {
    newLevel = 4; newLabel = '高風險';
    summary = '⚠️ 多項風險因子累積，請謹慎判斷';
    factors.hasCriticalCluster = true;
  } else if (risk >= ENGINE_THRESHOLDS.risk_l3_high) {
    newLevel = 3; newLabel = '未知網域（偏高風險）';
    summary = '⚠️ 有若干風險跡象，建議查證後再使用';
  } else if (risk >= ENGINE_THRESHOLDS.risk_l3) {
    newLevel = 3; newLabel = '未知網域';
    summary = '⚠️ 部分驗證項目無法完成比對，安全性尚無法確認，請謹慎判斷';
  } else if (checkSafeScoring(factors, risk)) {
    newLevel = 2; newLabel = '安心信任';
    summary = '✅ 深度分析後判斷為低風險網域';
  } else {
    newLevel = 3; newLabel = '未知網域';
    summary = '⚠️ 部分驗證項目無法完成比對，安全性尚無法確認，請謹慎判斷';
  }

  // ── P1-01：Fail-Cautious 安全地板 ──
  // 當多數外部 API 失敗時，資料不足以做出安全判斷，強制保守
  if (factors.apiFailCount >= 4) {
    // 幾乎全掛：強制 L3 偏高，絕不允許 L2
    if (newLevel <= 2) {
      newLevel = 3; newLabel = '未知網域（資料不足）';
      summary = '⚠️ 多項資安資料庫暫時無法存取，無法確認此網站的安全性，請特別謹慎';
      triggered.push('FAIL_CAUTIOUS_CRITICAL');
    }
  } else if (factors.apiFailCount >= 3) {
    // 過半失敗：不允許 L2
    if (newLevel <= 2) {
      newLevel = 3; newLabel = '未知網域（資料不足）';
      summary = '⚠️ 部分資安資料庫暫時無法存取，安全性尚無法完全確認';
      triggered.push('FAIL_CAUTIOUS');
    }
  }

  // ══════════════════════════════════════
  // 組合分析報告（v2.3：分層輸出）
  // ══════════════════════════════════════

  // ── 內部 trace（只寫入 server log，不送前端）──
  const decisionPath = p0Hit ? `P0.${p0Hit.code} → L5`
    : (triggered.length > 0 && newLevel === 5) ? `P1/P2.${triggered[triggered.length - 1]} → L5`
    : clusterHit ? `${clusterHit.code} → L${newLevel}`
    : `P5(Risk=${(risk*100).toFixed(1)}%) → L${newLevel}`;

  const apiStatus = {
    ip: ipRes.status === 'fulfilled' ? 'ok' : 'fail',
    whois: whoisRes.status === 'fulfilled' ? 'ok' : 'fail',
    vt: vtRes.status === 'fulfilled' ? 'ok' : 'fail',
    dns: dnsRes.status === 'fulfilled' ? 'ok' : 'fail',
    ipqs: ipqsRes.status === 'fulfilled' ? 'ok' : 'fail',
  };

  const internalTrace = {
    domain: clean,
    decision_path: decisionPath,
    triggered_rules: triggered,
    risk_groups_raw: { g1: +r1.toFixed(3), g2: +r2.toFixed(3), g3: +r3.toFixed(3), g4: +r4.toFixed(3), g5: +r5.toFixed(3), g6: +r6.toFixed(3) },
    risk_final: +risk.toFixed(4),
    api_status: apiStatus,
    correlation_applied: (r5 <= 0 && r6 <= 0),
    new_site_cap_applied: (r5 <= 0 && r6 <= 0 && r3 <= 0.08),
    level: newLevel,
    timestamp: new Date().toISOString(),
    engine_version: '3.0',
    dom_scan_used: !!req.body.dom_scan,
  };

  // 寫入 server log（內部審計用，不對外暴露）
  console.log(`[TRACE] ${JSON.stringify(internalTrace)}`);

  // ── 公開報告（只給前端看的白話文）──
  const publicReport = buildPublicReport(clean, checks, summary, triggered, crawlerP0, factors);

  // ── 公開風險群組（只給等級標籤，不給精確數值）──
  const publicRiskGroups = {
    age:        riskTier(r1),
    whois:      riskTier(r2),
    asn:        riskTier(r3),
    ssl:        riskTier(r4),
    reputation: riskTier(r5),
    behavior:   riskTier(r6),
  };

  // v2.3：風險百分比必須與最終等級一致，避免「L5 但只有 45%」的矛盾
  let finalRisk = +risk.toFixed(2);
  if (newLevel === 5 && finalRisk < 0.85) {
    finalRisk = Math.max(0.85, +(clusterHit?.confidence || 0.90).toFixed(2));
  } else if (newLevel === 4 && finalRisk < 0.65) {
    finalRisk = Math.max(0.65, +(clusterHit?.confidence || 0.75).toFixed(2));
  }

  // v3.0：賭博/成人/高風險加密貨幣 警示
  const warnings = detectWarningKeywords(clean);

  // P2-06：設定等級供 trackStats 的 finish handler 使用
  res.locals.trustintLevel = newLevel;

  const responseData = {
    status: 'ok',
    report: publicReport,
    newLevel, newLabel,
    should_block: newLevel >= 4,
    risk_score: finalRisk,
    risk_groups: publicRiskGroups,
    // v3.0：高風險內容警示
    warnings: warnings.length > 0 ? warnings.map(w => ({
      category: w.category,
      message: w.category === 'gambling' ? '⚠️ 此網站域名含有博弈/娛樂城相關字樣，請留意是否為合法業者' :
               w.category === 'adult' ? '⚠️ 此網站域名含有成人內容相關字樣' :
               w.category === 'crypto_risk' ? '⚠️ 此網站域名含有高風險加密貨幣相關字樣，請特別小心' : '',
    })) : [],
  };

  // P3-06：resolve dedup Promise，讓等待中的請求取得結果
  if (resolveDedup) resolveDedup(responseData);
  clearTimeout(dedupCleanup);
  pendingDeepAnalyze.delete(clean);

  // 寫入快取
  setCachedResult(clean, newLevel, newLabel, finalRisk);

  return res.json(responseData);
});

// ── v2.3：風險等級標籤函式（取代精確數值，防止逆向工程）──
function riskTier(val) {
  if (val <= 0)    return 'safe';      // 正常 / 信任加分
  if (val <= 0.10) return 'safe';      // 正常
  if (val <= 0.20) return 'low';       // 輕微
  if (val <= 0.30) return 'medium';    // 偏高
  if (val <= 0.40) return 'high';      // 異常
  return 'critical';                    // 嚴重
}

// ── v2.3：公開報告組裝（只輸出白話文摘要，不暴露任何技術細節）──
function buildPublicReport(domain, checks, summary, triggered = [], crawlerP0 = null, factors = {}) {
  // v3.0 設計原則：
  // ❌ 不公開：技術參數、P5 分數、群權重、API 名稱、規則代號
  // ✅ 公開：質化警示（用白話文讓用戶學會辨識詐騙特徵）
  // ✅ 公開：量化結論（風險等級、百分比，但不解釋計算方式）

  const sections = [];

  // ── 第一區：總結 ──
  const riskItems = checks.filter(c => c.startsWith('🔴') || c.startsWith('⚠️')).length;
  const safeItems = checks.filter(c => c.startsWith('✅')).length;

  let detailSummary = '';
  if (riskItems === 0 && safeItems > 0) {
    detailSummary = '經多項資安資料庫交叉比對，目前未發現明顯風險指標。';
  } else if (riskItems >= 4) {
    detailSummary = '經多項資安資料庫交叉比對，偵測到多項風險指標，請務必提高警覺。';
  } else if (riskItems >= 2) {
    detailSummary = '經多項資安資料庫交叉比對，偵測到若干可疑特徵，建議謹慎判斷。';
  } else if (riskItems >= 1) {
    detailSummary = '經多項資安資料庫交叉比對，偵測到少量可疑特徵，建議查證後再使用。';
  } else {
    detailSummary = '目前可供比對的資料有限，無法做出明確判定，建議謹慎使用。';
  }
  sections.push(`<strong>🔍 深度分析：${domain}</strong><br><br>${detailSummary}`);

  // ── 第二區：質化警示（用戶看得懂的可疑特徵）──
  const qualWarnings = [];

  // 域名特徵
  if (triggered.includes('TLD_TIER2_UNKNOWN'))
    qualWarnings.push('🔸 此網站使用高風險網域後綴，且不在任何已知安全網站資料庫中');
  if (triggered.includes('FAKE_GOV_DOMAIN'))
    qualWarnings.push('🔸 此網站域名疑似仿冒政府機關（.gov.tw），但並非真正的政府網站');
  if (triggered.includes('BRAND_SPOOF'))
    qualWarnings.push('🔸 此網站域名與知名品牌極為相似，可能是仿冒網站');
  if (triggered.includes('SUSPICIOUS_PATTERN'))
    qualWarnings.push('🔸 此網站域名含有「退款」「驗證」「獎品」等常見詐騙關鍵字');

  // 爬蟲偵測到的頁面內容
  if (crawlerP0 && crawlerP0.rules && crawlerP0.rules.length > 0) {
    for (const rule of crawlerP0.rules) {
      const cat = rule.category;
      const kw = (rule.keywords || []).slice(0, 3).join('、');
      
      if (cat === 'investment_scam')
        qualWarnings.push(`🔸 頁面出現投資詐騙常見用語：「${kw}」等，疑似假投資平台`);
      else if (cat === 'impersonation')
        qualWarnings.push(`🔸 頁面出現仿冒官方的緊急通知用語：「${kw}」等，請向官方管道確認`);
      else if (cat === 'prize_scam')
        qualWarnings.push(`🔸 頁面出現中獎/抽獎詐騙常見用語：「${kw}」等，正規企業不會這樣通知中獎`);
      else if (cat === 'romance_scam')
        qualWarnings.push(`🔸 頁面出現交友誘導用語：「${kw}」等，請注意感情詐騙風險`);
      else if (cat === 'loan_scam')
        qualWarnings.push(`🔸 頁面出現貸款詐騙常見用語：「${kw}」等，正規銀行不會保證過件`);
      else if (cat === 'fake_shop')
        qualWarnings.push(`🔸 頁面出現一頁式購物詐騙特徵：「${kw}」等，請確認賣家是否為合法商家`);
      else if (cat === 'fake_support')
        qualWarnings.push('🔸 頁面出現假技術支援/假病毒警告，這是常見的恐嚇式詐騙手法');
      else if (cat === 'pig_butchering')
        qualWarnings.push(`🔸 頁面出現殺豬盤常見用語：「${kw}」等，疑似投資詐騙群組導流`);
      else if (cat === 'fake_alert')
        qualWarnings.push('🔸 頁面含有假病毒或假下載警告，請勿依指示操作');
      else if (cat === 'sensitive_form' || cat === 'sensitive_no_company')
        qualWarnings.push('🔸 頁面要求輸入信用卡、身分證或銀行帳號等敏感資料，但查無公司登記資訊');
      else if (cat === 'unsafe_payment')
        qualWarnings.push('🔸 頁面有付款功能但未使用知名第三方支付平台（如 ECPay、Stripe），請勿輸入卡號');
      else if (cat === 'unknown_crypto_platform')
        qualWarnings.push('🔸 此網站具有虛擬貨幣交易平台特徵，但非金管會核准的合法交易所');
      else if (cat === 'unknown_investment_platform')
        qualWarnings.push('🔸 此網站具有投資平台特徵，但非已知合法金融機構，請向金管會查證');
      else if (cat === 'romance_scam_platform')
        qualWarnings.push('🔸 此網站同時有聊天室和付款功能，且查無公司資訊，高度疑似感情詐騙平台');
      else if (cat === 'cross_domain_redirect')
        qualWarnings.push('🔸 此網站會將你轉導到其他域名，可能是詐騙導流手法');
      else if (cat === 'ua_cloaking')
        qualWarnings.push('🔸 此網站對不同裝置顯示不同內容，可能在隱藏真實頁面');
    }
  }

  // 爬蟲偵測到的頁面品質問題
  if (triggered.includes('NO_LEGAL_PAGES'))
    qualWarnings.push('🔸 此網站缺少隱私政策、服務條款等基本法律頁面');
  if (triggered.includes('NO_IDENTITY'))
    qualWarnings.push('🔸 此網站查無公司名稱、客服電話或實體地址');
  if (triggered.includes('NO_HTTPS'))
    qualWarnings.push('🔸 此網站未使用 HTTPS 加密，你的資料傳輸可能被竊取');
  if (triggered.includes('LOW_QUALITY_PAGE'))
    qualWarnings.push('🔸 此網站製作粗糙、缺少基本網頁元素，不像正常營運的網站');
  if (triggered.includes('CROSS_DOMAIN_REDIRECT'))
    qualWarnings.push('🔸 此網站會將你重新導向到其他網域');
  if (triggered.includes('UNSAFE_PAYMENT'))
    qualWarnings.push('🔸 此網站有收款功能但未使用知名支付平台');
  if (triggered.includes('UNKNOWN_CRYPTO'))
    qualWarnings.push('🔸 偵測到虛擬貨幣交易相關功能，請確認是否為合法交易所');
  if (triggered.includes('UNKNOWN_INVESTMENT'))
    qualWarnings.push('🔸 偵測到投資交易相關功能，請確認是否為合法金融機構');

  // v3.0 BHR 強因子警示
  if (triggered.includes('HOLLOW_SHELL'))
    qualWarnings.push('🔸 此網站超過半數連結無法點擊，疑似快速搭建的詐騙頁面，正規網站不會這樣');
  if (triggered.includes('ANTI_ANALYSIS'))
    qualWarnings.push('🔸 此網站禁止右鍵或封鎖開發者工具，正規金融機構不會這樣做，可能在隱藏詐騙內容');
  if (triggered.includes('SIDELOAD'))
    qualWarnings.push('🔸 此網站提供 APP 安裝檔（.apk/.exe）下載，正規 APP 應透過 App Store 或 Google Play 安裝');
  if (triggered.includes('SEED_PHRASE'))
    qualWarnings.push('🔸 此網站要求輸入助記詞或私鑰，任何正規平台都不會要求你提供這些資訊，這是竊取虛擬貨幣的詐騙手法');
  if (triggered.includes('AD_TRAFFIC_SCAM'))
    qualWarnings.push('🔸 此網站透過社群廣告（TikTok/Facebook/Google）導流到新註冊的高風險域名，這是一頁式詐騙的典型手法');
  if (triggered.includes('PIG_BUTCHERING_COMBO'))
    qualWarnings.push('🔸 同時偵測到交友誘導和投資推銷語意，這是「殺豬盤」詐騙的典型模式——先培養感情再誘導投資');

  // 爬蟲 P0 語意類別警示
  if (crawlerP0 && crawlerP0.rules) {
    for (const rule of crawlerP0.rules) {
      if (rule.category === 'job_scam')
        qualWarnings.push('🔸 頁面出現求職詐騙常見用語，正規公司不會要求繳交保證金或制服費');
      if (rule.category === 'charity_scam')
        qualWarnings.push('🔸 頁面出現捐款/公益相關用語，捐款請透過官方認證的慈善機構管道');
      if (rule.category === 'fake_buyer')
        qualWarnings.push('🔸 頁面出現假買家/假退款常見用語（取消分期、訂單異常），請直接在購物平台APP內確認訂單狀態');
      if (rule.category === 'recovery_scam')
        qualWarnings.push('🔸 頁面宣稱可追回被騙資金，這是專門針對詐騙受害者的「二次詐騙」，官方機關不會委託私人追款');
      if (rule.category === 'account_freeze')
        qualWarnings.push('🔸 頁面宣稱你的帳戶被凍結或異常，請直接撥打銀行客服專線確認，不要透過此網站操作');
    }
  }

  // 去重
  const uniqueWarnings = [...new Set(qualWarnings)];

  if (uniqueWarnings.length > 0) {
    sections.push('<br><strong>⚠️ 偵測到以下可疑特徵：</strong><br>' +
      uniqueWarnings.map(w => `<span style="display:block;margin:4px 0;font-size:0.88rem;line-height:1.6">${w}</span>`).join(''));
  }

  // ── 第三區：結論 ──
  sections.push(`<br><strong>${summary}</strong>`);

  // ── 第四區：L3/L4 驗證提示（僅非白名單站顯示）──
  // 用 triggered 判斷 level：有 clusterHit 代表 L4+，否則看風險分數
  const hasHighRisk = triggered.some(t => ['TLD_TIER2_UNKNOWN','FAKE_GOV_DOMAIN','SUSPICIOUS_PATTERN',
    'BRAND_SPOOF','SENSITIVE_NO_COMPANY','UNSAFE_PAYMENT','UNKNOWN_CRYPTO','UNKNOWN_INVESTMENT'].includes(t));
  const isUnknown = !hasHighRisk && triggered.length === 0;
  if (hasHighRisk || isUnknown) {
    sections.push('<br><div style="margin-top:8px;padding:10px 14px;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;font-size:0.78rem;color:#64748B;line-height:1.6;text-align:center">' +
      '如果您確認這是合法網站，可建議網站經營者透過 <a href="https://trustint.org/verify.html" target="_blank" style="color:#2563EB;text-decoration:underline">TrustInt 官方驗證（免費）</a>，通過後將獲得 L1 身分驗證標章。' +
      '</div>');
  }

  return sections.join('');
}

// ════════════════════════════════════════
// API：FP/FN 回報系統（v2.5：PostgreSQL）
// ════════════════════════════════════════
const fpfnRateLimit = new Map(); // IP -> { domain -> timestamp }（暫時保留記憶體限流）

// P2-08：每小時清理 fpfnRateLimit 中超過 24 小時的舊紀錄
setInterval(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  let cleaned = 0;
  for (const [key, ts] of fpfnRateLimit) {
    if (ts < cutoff) { fpfnRateLimit.delete(key); cleaned++; }
  }
  if (cleaned > 0) console.log(`🧹 fpfnRateLimit 清理：${cleaned} 筆`);
}, 60 * 60 * 1000);

app.post('/v1/report', async (req, res) => {
  const { domain, reason, report_type, original_level, triggered_rules, user_comment } = req.body;
  if (!domain) return res.status(400).json({ status: 'error', message: '請提供網域' });

  const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
  
  // v2.3：同一 IP 每日每個網域只能回報一次
  const ip = req.ip;
  const today = new Date().toISOString().split('T')[0];
  const key = `${ip}:${cleanDomain}:${today}`;
  if (fpfnRateLimit.has(key)) {
    return res.json({ status: 'ok', message: '您已回報過此網域，感謝您的貢獻' });
  }
  fpfnRateLimit.set(key, Date.now());

  // 正規化 report_type
  let normalizedType = 'unknown';
  const rt = (report_type || reason || '').toLowerCase();
  if (rt.includes('false_positive') || rt.includes('fp') || rt.includes('誤判') || rt.includes('安全')) {
    normalizedType = 'fp';
  } else if (rt.includes('false_negative') || rt.includes('fn') || rt.includes('漏判') || rt.includes('詐騙')) {
    normalizedType = 'fn';
  }

  console.log(`📋 FP/FN 回報：${normalizedType} | ${cleanDomain} | L${original_level} | rules: [${(triggered_rules||[]).join(',')}] | comment: ${(user_comment||'').slice(0,50)}`);

  // V2-AI：記錄校正信號
  recordCalibrationSignal(cleanDomain, normalizedType === 'fp' ? 'false_positive' : 'false_negative', original_level || 3);

  // V2.5：寫入 PostgreSQL
  try {
    const domainId = await getOrCreateDomainId(cleanDomain);
    if (domainId) {
      await pool.query(`
        INSERT INTO reports (domain_id, report_type, original_level, user_comment)
        VALUES ($1, $2, $3, $4)
      `, [domainId, normalizedType, original_level || null, (user_comment || '').slice(0, 500)]);

      // 更新 domains 表的 fp_count / fn_count
      if (normalizedType === 'fp') {
        await pool.query('UPDATE domains SET fp_count = fp_count + 1, updated_at = NOW() WHERE id = $1', [domainId]);
      } else if (normalizedType === 'fn') {
        await pool.query('UPDATE domains SET fn_count = fn_count + 1, updated_at = NOW() WHERE id = $1', [domainId]);
      }

      // 檢查 FN 回報數，自動升級
      const countRes = await pool.query('SELECT fn_count, fp_count FROM domains WHERE id = $1', [domainId]);
      if (countRes.rows.length > 0) {
        const { fn_count, fp_count } = countRes.rows[0];
        if (fn_count >= 3 && fp_count === 0) {
          console.log(`🚨 自動升級：${cleanDomain} 收到 ${fn_count} 次 FN 回報，暫列入觀察`);
        }
      }
    }
  } catch (err) {
    console.error('報告寫入 DB 失敗：', err.message);
  }

  return res.json({ 
    status: 'ok', 
    message: '感謝您的回報，我們將盡快審查並改善判定準確度',
  });
});

// v2.5：查詢特定網域的回報狀況（Extension 用）- PostgreSQL 版
app.get('/v1/report/domain/:domain', async (req, res) => {
  const domain = req.params.domain?.toLowerCase().replace(/^www\./, '');
  if (!domain) return res.status(400).json({ status: 'error' });

  try {
    const result = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE report_type = 'fp' AND reported_at > NOW() - INTERVAL '30 days') as fp_count,
        COUNT(*) FILTER (WHERE report_type = 'fn' AND reported_at > NOW() - INTERVAL '30 days') as fn_count,
        COUNT(*) FILTER (WHERE reported_at > NOW() - INTERVAL '30 days') as total_count
      FROM reports r
      JOIN domains d ON d.id = r.domain_id
      WHERE d.domain = $1
    `, [domain]);

    const row = result.rows[0] || { fp_count: 0, fn_count: 0, total_count: 0 };
    return res.json({
      status: 'ok',
      domain,
      report_count_30d: parseInt(row.total_count),
      false_positives: parseInt(row.fp_count),
      false_negatives: parseInt(row.fn_count),
    });
  } catch (err) {
    console.error('查詢回報失敗：', err.message);
    return res.json({
      status: 'ok',
      domain,
      report_count_30d: 0,
      false_positives: 0,
      false_negatives: 0,
    });
  }
});

// v2.5：FP/FN 統計 API（內部儀表板用）- PostgreSQL 版
app.get('/v1/fpfn-stats', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE report_type = 'fp') as fp_count,
        COUNT(*) FILTER (WHERE report_type = 'fn') as fn_count,
        COUNT(*) as total_count,
        COUNT(*) FILTER (WHERE reviewed = false) as pending_review
      FROM reports
    `);

    const row = result.rows[0] || {};
    return res.json({
      status: 'ok',
      false_positives: parseInt(row.fp_count) || 0,
      false_negatives: parseInt(row.fn_count) || 0,
      total_reports: parseInt(row.total_count) || 0,
      pending_review: parseInt(row.pending_review) || 0,
    });
  } catch (err) {
    console.error('統計查詢失敗：', err.message);
    return res.json({
      status: 'ok',
      false_positives: 0,
      false_negatives: 0,
      total_reports: 0,
    });
  }
});

// 每日清理 FP/FN rate limit（保留回報紀錄）
setInterval(() => {
  const now = Date.now();
  for (const [key, ts] of fpfnRateLimit) {
    if (now - ts > 86400000) fpfnRateLimit.delete(key);
  }
}, 60 * 60 * 1000);

// ════════════════════════════════════════
// API：白名單申請
// ════════════════════════════════════════
app.post('/v1/whitelist/apply', async (req, res) => {
  const { applicant_type, company_name, tax_id, domain,
          contact_email, note, recaptcha_token } = req.body;

  if (!domain || !contact_email)
    return res.status(400).json({ status: 'error', message: '請填寫必填欄位' });

  if (recaptcha_token) {
    const valid = await verifyRecaptcha(recaptcha_token);
    if (!valid) return res.status(400).json({ status: 'error', message: '人機驗證失敗，請重試' });
  }

  console.log('=== 新白名單申請 ===');
  console.log(`類型: ${applicant_type} | 網域: ${domain} | Email: ${contact_email}`);
  console.log('===================');

  return res.json({ status: 'ok', message: '申請已收到，我們將在 3 個工作天內審核' });
});

// ════════════════════════════════════════
// V2.5：L1 官方驗證系統（PostgreSQL 版）
// DNS TXT 記錄驗證流程
// ════════════════════════════════════════

// 記憶體快取（加速查詢，DB 為主要來源）
const l1VerifiedDomainsCache = new Set();
const l1PendingCache = new Map(); // domain -> { token, created }

// P2-07：每小時清理 l1PendingCache 中超過 24 小時的殭屍 token
setInterval(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  let cleaned = 0;
  for (const [domain, data] of l1PendingCache) {
    if (data.created < cutoff) { l1PendingCache.delete(domain); cleaned++; }
  }
  // v3.0.1：強制上限 1000 筆，防攻擊者打 /apply 塞爆
  if (l1PendingCache.size > 1000) {
    const excess = l1PendingCache.size - 500;
    let count = 0;
    for (const key of l1PendingCache.keys()) {
      if (count >= excess) break;
      l1PendingCache.delete(key);
      count++;
    }
    cleaned += count;
    console.log(`[WARN] l1PendingCache 超過 1000，強制清理 ${count} 筆`);
  }
  if (cleaned > 0) console.log(`🧹 l1PendingCache 清理：${cleaned} 筆過期 token`);
}, 60 * 60 * 1000);

// P2-07：L1 申請 IP 限流（每 IP 每日最多 5 個域名）
const l1ApplyRateLimit = new Map(); // ip -> { count, date }
setInterval(() => {
  const today = new Date().toISOString().split('T')[0];
  for (const [ip, data] of l1ApplyRateLimit) {
    if (data.date !== today) l1ApplyRateLimit.delete(ip);
  }
}, 60 * 60 * 1000);

// 啟動時從 DB 載入 L1 驗證網域
async function loadL1DomainsFromDB() {
  try {
    const result = await pool.query(`
      SELECT domain FROM domains 
      WHERE is_l1_verified = true 
        AND (l1_expires IS NULL OR l1_expires > NOW())
    `);
    result.rows.forEach(row => l1VerifiedDomainsCache.add(row.domain));
    console.log(`✅ L1 驗證網域載入：${l1VerifiedDomainsCache.size} 個`);
  } catch (err) {
    console.log('⚠️ L1 驗證資料載入失敗：', err.message);
  }
}

// 產生驗證 token
function generateVerifyToken() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < 32; i++) {
    token += chars[Math.floor(Math.random() * chars.length)];
  }
  return token;
}

// v3.0：經濟部商工 API 統編驗證
async function verifyTaxId(taxId) {
  if (!taxId || !/^\d{8}$/.test(taxId)) {
    return { valid: false, error: '統一編號格式錯誤（應為 8 碼數字）' };
  }
  try {
    // 公司登記 API
    const companyUrl = `https://data.gcis.nat.gov.tw/od/data/api/5F64D864-61CB-4D0D-8902-B6D4B7AD803C?$format=json&$filter=Business_Accounting_NO eq ${taxId}`;
    const res = await axios.get(companyUrl, { timeout: 10000 });
    
    if (res.data && res.data.length > 0) {
      const company = res.data[0];
      const status = company.Company_Status_Desc || company.Company_Status || '';
      const name = company.Company_Name || '';
      const addr = company.Company_Location || '';
      const isActive = status === '核准設立' || status === '營業中' || status.includes('核准');
      
      return {
        valid: true,
        source: 'gcis_company',
        tax_id: taxId,
        name,
        status,
        address: addr,
        is_active: isActive,
        warning: isActive ? null : `公司狀態為「${status}」，非營業中`,
      };
    }

    // 商業登記 API（獨資/合夥商號）
    const businessUrl = `https://data.gcis.nat.gov.tw/od/data/api/F05D1060-7D57-4763-BDCE-0DAF5975AFE0?$format=json&$filter=Business_Accounting_NO eq ${taxId}`;
    const res2 = await axios.get(businessUrl, { timeout: 10000 });

    if (res2.data && res2.data.length > 0) {
      const biz = res2.data[0];
      const status = biz.Business_Current_Status_Desc || biz.Business_Current_Status || '';
      const name = biz.Business_Name || '';
      const addr = biz.Business_Address || '';
      const isActive = status === '營業中' || status === '核准設立';

      return {
        valid: true,
        source: 'gcis_business',
        tax_id: taxId,
        name,
        status,
        address: addr,
        is_active: isActive,
        warning: isActive ? null : `商號狀態為「${status}」，非營業中`,
      };
    }

    return { valid: false, error: '查無此統一編號的公司或商號登記' };
  } catch (e) {
    console.error(`[GCIS] 商工 API 查詢失敗：${e.message}`);
    return { valid: false, error: `商工 API 查詢失敗：${e.message}` };
  }
}

// v3.0：每日檢查 L1-Verified 公司的營業狀態，自動撤銷已停業/歇業/解散的
async function dailyL1BusinessCheck() {
  try {
    const verified = await pool.query(
      `SELECT domain, l1_tax_id, l1_org_name FROM domains 
       WHERE is_l1_verified = true AND l1_tax_id IS NOT NULL`
    );
    
    let revoked = 0;
    for (const row of verified.rows) {
      const result = await verifyTaxId(row.l1_tax_id);
      if (result.valid && !result.is_active) {
        // 公司不再營業中 → 撤銷 L1
        await pool.query(
          `UPDATE domains SET is_l1_verified = false, updated_at = NOW() WHERE domain = $1`,
          [row.domain]
        );
        l1VerifiedDomainsCache.delete(row.domain);
        resultCache.delete(row.domain);
        revoked++;
        console.log(`[L1] ⚠️ 自動撤銷：${row.domain}（${row.l1_org_name}）→ 公司狀態：${result.status}`);
      }
      // Rate limit：每個查詢間隔 1 秒，避免打爆商工 API
      await new Promise(r => setTimeout(r, 1000));
    }
    
    if (revoked > 0) {
      console.log(`[L1] 每日檢查完成：${verified.rows.length} 筆驗證，${revoked} 筆撤銷`);
    }
  } catch (e) {
    console.error(`[L1] 每日檢查失敗：${e.message}`);
  }
}

// 每天凌晨 3 點執行
setInterval(dailyL1BusinessCheck, 24 * 60 * 60 * 1000);
// 啟動 30 秒後先跑一次
setTimeout(dailyL1BusinessCheck, 30000);

// DNS TXT 記錄查詢
async function checkDnsTxt(domain, expectedToken) {
  try {
    const res = await axios.get(`https://dns.google/resolve?name=${domain}&type=TXT`, { timeout: 5000 });
    if (res.data && res.data.Answer) {
      for (const ans of res.data.Answer) {
        const txt = (ans.data || '').replace(/"/g, '').trim();
        if (txt === `trustint-verify=${expectedToken}`) {
          return { found: true, record: txt };
        }
      }
      return { found: false, records: res.data.Answer.map(a => a.data) };
    }
    return { found: false, records: [] };
  } catch (e) {
    return { found: false, error: e.message };
  }
}

// API：申請 L1 驗證（產生 token）
app.post('/v1/l1/apply', async (req, res) => {
  const { domain, email, organization, tax_id } = req.body;

  if (!domain || !email) {
    return res.status(400).json({ 
      status: 'error', 
      message: '請填寫網域和聯絡 Email' 
    });
  }

  // P2-07：IP 限流（每 IP 每日最多 5 個域名申請）
  const applyIp = req.ip;
  const today = new Date().toISOString().split('T')[0];
  const ipRecord = l1ApplyRateLimit.get(applyIp);
  if (ipRecord && ipRecord.date === today && ipRecord.count >= 5) {
    return res.status(429).json({
      status: 'error',
      message: '每日申請次數已達上限（5 次），請明天再試'
    });
  }

  const clean = domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];

  // v3.0：如果提供統編，先向商工 API 驗證
  let gcisResult = null;
  if (tax_id) {
    gcisResult = await verifyTaxId(tax_id.trim());
  }

  try {
    const existingL1 = await pool.query(
      'SELECT is_l1_verified, l1_expires, l1_tier FROM domains WHERE domain = $1',
      [clean]
    );
    
    if (existingL1.rows.length > 0 && existingL1.rows[0].is_l1_verified) {
      const expires = existingL1.rows[0].l1_expires;
      if (!expires || new Date(expires) > new Date()) {
        return res.json({ 
          status: 'already_verified', 
          message: '此網域已通過 L1 驗證',
          tier: existingL1.rows[0].l1_tier || 'basic',
        });
      }
    }

    let pendingToken = l1PendingCache.get(clean);
    if (pendingToken) {
      const age = Date.now() - pendingToken.created;
      if (age < 24 * 60 * 60 * 1000) {
        return res.json({
          status: 'pending',
          message: '您已有進行中的申請，請完成 DNS 驗證',
          token: pendingToken.token,
          dns_record: `trustint-verify=${pendingToken.token}`,
          tier: tax_id && gcisResult?.valid ? 'verified' : 'basic',
          gcis: gcisResult || null,
        });
      }
    }

    const dbPending = await pool.query(
      `SELECT l1_token, created_at FROM domains 
       WHERE domain = $1 AND l1_token IS NOT NULL 
         AND created_at > NOW() - INTERVAL '24 hours'`,
      [clean]
    );
    
    if (dbPending.rows.length > 0 && dbPending.rows[0].l1_token) {
      const token = dbPending.rows[0].l1_token;
      l1PendingCache.set(clean, { token, created: new Date(dbPending.rows[0].created_at).getTime() });
      return res.json({
        status: 'pending',
        message: '您已有進行中的申請，請完成 DNS 驗證',
        token,
        dns_record: `trustint-verify=${token}`,
      });
    }

    // 產生新 token
    const token = generateVerifyToken();
    const now = Date.now();
    const tier = (tax_id && gcisResult?.valid) ? 'verified' : 'basic';
    
    // 寫入 DB（新增 tax_id, l1_tier, l1_org_name 欄位）
    await pool.query(`
      INSERT INTO domains (domain, l1_token, l1_email, l1_tax_id, l1_org_name, l1_tier, is_l1_verified, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, false, NOW(), NOW())
      ON CONFLICT (domain) DO UPDATE SET 
        l1_token = $2, l1_email = $3, l1_tax_id = $4, l1_org_name = $5, l1_tier = $6,
        is_l1_verified = false, updated_at = NOW()
    `, [clean, token, email, tax_id || null, gcisResult?.name || organization || null, tier]);

    l1PendingCache.set(clean, { token, created: now });

    const curRecord = l1ApplyRateLimit.get(applyIp);
    if (curRecord && curRecord.date === today) {
      curRecord.count++;
    } else {
      l1ApplyRateLimit.set(applyIp, { count: 1, date: today });
    }

    console.log(`[L1] 新申請：${clean} | Email: ${email} | Tier: ${tier}${tax_id ? ' | 統編: ' + tax_id : ''}`);

    return res.json({
      status: 'ok',
      message: '申請成功，請完成 DNS 驗證',
      domain: clean,
      token,
      tier,
      gcis: gcisResult || null,
      dns_record: `trustint-verify=${token}`,
      instructions: [
        `1. 登入您的 DNS 管理後台（如 Cloudflare、GoDaddy、Gandi 等）`,
        `2. 新增一筆 TXT 記錄`,
        `3. 名稱/主機：@ 或 ${clean}`,
        `4. 類型：TXT`,
        `5. 值：trustint-verify=${token}`,
        `6. 儲存後等待 DNS 生效（通常 5-30 分鐘）`,
        `7. 回到此頁面點擊「驗證」按鈕`
      ],
      expires_in: '24 小時'
    });
  } catch (err) {
    console.error('[L1] 申請錯誤：', err.message);
    return res.status(500).json({ status: 'error', message: '系統錯誤，請稍後再試' });
  }
});

// API：驗證 DNS TXT 記錄
app.post('/v1/l1/verify', async (req, res) => {
  const { domain } = req.body;

  if (!domain) {
    return res.status(400).json({ status: 'error', message: '請提供網域' });
  }

  const clean = domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];

  try {
    // 從 DB 取得 token
    const result = await pool.query(
      `SELECT id, l1_token, created_at FROM domains 
       WHERE domain = $1 AND l1_token IS NOT NULL`,
      [clean]
    );

    if (result.rows.length === 0 || !result.rows[0].l1_token) {
      return res.status(400).json({ 
        status: 'error', 
        message: '找不到此網域的申請紀錄，請先申請 L1 驗證' 
      });
    }

    const { id: domainId, l1_token: token, created_at } = result.rows[0];

    // 檢查 token 是否過期（24 小時）
    const age = Date.now() - new Date(created_at).getTime();
    if (age > 24 * 60 * 60 * 1000) {
      await pool.query('UPDATE domains SET l1_token = NULL WHERE id = $1', [domainId]);
      l1PendingCache.delete(clean);
      return res.status(400).json({ 
        status: 'expired', 
        message: '驗證 token 已過期，請重新申請' 
      });
    }

    // 查詢 DNS TXT 記錄
    const dnsResult = await checkDnsTxt(clean, token);

    if (dnsResult.found) {
      // 驗證成功
      const now = new Date();
      const oneYear = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

      // 取得 tier 和 org info
      const domainInfo = await pool.query(
        'SELECT l1_tier, l1_tax_id, l1_org_name FROM domains WHERE id = $1', [domainId]
      );
      const tier = domainInfo.rows[0]?.l1_tier || 'basic';
      const orgName = domainInfo.rows[0]?.l1_org_name || null;
      const taxId = domainInfo.rows[0]?.l1_tax_id || null;
      
      // 更新 DB
      await pool.query(`
        UPDATE domains SET 
          is_l1_verified = true,
          l1_expires = $1,
          l1_token = NULL,
          updated_at = NOW()
        WHERE id = $2
      `, [oneYear, domainId]);

      // 更新快取
      l1VerifiedDomainsCache.add(clean);
      l1PendingCache.delete(clean);
      resultCache.delete(clean);

      console.log(`[L1] ✅ 驗證成功：${clean} | Tier: ${tier}${orgName ? ' | ' + orgName : ''}`);

      const tierLabel = tier === 'verified' ? '身分已驗證（含統編）' : '身分已驗證（DNS）';

      return res.json({
        status: 'verified',
        message: '🎉 恭喜！您的網域已通過 TrustInt 身分驗證',
        domain: clean,
        level: 1,
        label: '官方已驗證',
        tier,
        tier_label: tierLabel,
        organization: orgName,
        tax_id: taxId,
        verified_at: now.toISOString(),
        expires_at: oneYear.toISOString(),
        disclaimer: '身分驗證僅代表網站經營者身分可追溯，不代表 TrustInt 為其商業行為背書。',
        next_steps: [
          `您的網域現在會顯示為「L1 ${tierLabel}」`,
          tier === 'verified' ? '經營者資訊（公司名稱）將公開顯示於驗證標章中' : '建議提供統一編號升級為完整驗證，將顯示公司名稱',
          '驗證有效期為 1 年',
          '如公司狀態變更（停業/歇業/解散），驗證將自動失效',
        ]
      });
    } else {
      // 驗證失敗
      return res.json({
        status: 'not_found',
        message: '未找到正確的 DNS TXT 記錄',
        expected: `trustint-verify=${token}`,
        found_records: dnsResult.records || [],
        tips: [
          'DNS 記錄可能需要 5-30 分鐘才會生效',
          '請確認 TXT 記錄的值完全正確（包含 trustint-verify= 前綴）',
          '如果使用 Cloudflare，請確認 DNS Only 模式（灰雲）'
        ]
      });
    }
  } catch (err) {
    console.error('[L1] 驗證錯誤：', err.message);
    return res.status(500).json({ status: 'error', message: '系統錯誤，請稍後再試' });
  }
});

// API：查詢 L1 狀態
app.get('/v1/l1/status/:domain', async (req, res) => {
  const clean = req.params.domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  
  try {
    const result = await pool.query(
      `SELECT is_l1_verified, l1_expires, l1_token, created_at 
       FROM domains WHERE domain = $1`,
      [clean]
    );

    if (result.rows.length > 0) {
      const row = result.rows[0];
      
      if (row.is_l1_verified && (!row.l1_expires || new Date(row.l1_expires) > new Date())) {
        return res.json({
          status: 'verified',
          domain: clean,
          level: 1,
          label: '官方已驗證',
          expires_at: row.l1_expires ? new Date(row.l1_expires).toISOString() : null
        });
      }

      if (row.l1_token) {
        const age = Date.now() - new Date(row.created_at).getTime();
        if (age < 24 * 60 * 60 * 1000) {
          return res.json({
            status: 'pending',
            domain: clean,
            message: '申請進行中，等待 DNS 驗證',
            token: row.l1_token,
            dns_record: `trustint-verify=${row.l1_token}`
          });
        }
      }
    }

    return res.json({
      status: 'not_applied',
      domain: clean,
      message: '此網域尚未申請 L1 驗證'
    });
  } catch (err) {
    console.error('[L1] 狀態查詢錯誤：', err.message);
    return res.json({
      status: 'not_applied',
      domain: clean,
      message: '此網域尚未申請 L1 驗證'
    });
  }
});

// API：列出所有 L1 網域（管理用）
app.get('/v1/l1/list', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT domain, l1_email, l1_expires, updated_at
      FROM domains 
      WHERE is_l1_verified = true 
        AND (l1_expires IS NULL OR l1_expires > NOW())
      ORDER BY updated_at DESC
    `);

    const domains = result.rows.map(row => ({
      domain: row.domain,
      email: row.l1_email,
      expires_at: row.l1_expires ? new Date(row.l1_expires).toISOString() : null,
      verified_at: new Date(row.updated_at).toISOString()
    }));

    return res.json({
      status: 'ok',
      count: domains.length,
      domains
    });
  } catch (err) {
    console.error('[L1] 列表查詢錯誤：', err.message);
    return res.json({ status: 'ok', count: 0, domains: [] });
  }
});

// 在 deep-analyze 中檢查 L1 狀態（使用快取）
function isL1Verified(domain) {
  return l1VerifiedDomainsCache.has(domain);
}

// 啟動時載入 L1 資料
loadL1DomainsFromDB();

// ════════════════════════════════════════
// API：健康檢查
// ════════════════════════════════════════
// ══════════════════════════════════════
// V2-07：服務監控（每日摘要 + 狀態頁 + UptimeRobot webhook）
// ══════════════════════════════════════

// 每日摘要：每天 00:05 自動寫入 PostgreSQL
let lastDailySummaryDate = '';
async function saveDailySummary() {
  const today = new Date().toISOString().split('T')[0];
  if (today === lastDailySummaryDate) return;
  
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS daily_stats (
        date DATE PRIMARY KEY,
        total_checks INT DEFAULT 0,
        total_deep_analyzes INT DEFAULT 0,
        total_blocks INT DEFAULT 0,
        unique_ips INT DEFAULT 0,
        level_1 INT DEFAULT 0,
        level_2 INT DEFAULT 0,
        level_3 INT DEFAULT 0,
        level_4 INT DEFAULT 0,
        level_5 INT DEFAULT 0,
        npa_size INT DEFAULT 0,
        openphish_size INT DEFAULT 0,
        engine_version VARCHAR(20) DEFAULT '3.0',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    
    await pool.query(`
      INSERT INTO daily_stats (date, total_checks, total_deep_analyzes, total_blocks, unique_ips,
        level_1, level_2, level_3, level_4, level_5, npa_size, openphish_size, engine_version)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (date) DO UPDATE SET
        total_checks = EXCLUDED.total_checks,
        total_deep_analyzes = EXCLUDED.total_deep_analyzes,
        total_blocks = EXCLUDED.total_blocks,
        unique_ips = EXCLUDED.unique_ips,
        level_1 = EXCLUDED.level_1, level_2 = EXCLUDED.level_2,
        level_3 = EXCLUDED.level_3, level_4 = EXCLUDED.level_4, level_5 = EXCLUDED.level_5,
        npa_size = EXCLUDED.npa_size, openphish_size = EXCLUDED.openphish_size,
        engine_version = EXCLUDED.engine_version
    `, [
      stats.todayDate,
      stats.todayChecks, stats.totalDeepAnalyzes, stats.todayBlocks,
      stats.uniqueIPs.size,
      stats.levelCounts[1] || 0, stats.levelCounts[2] || 0,
      stats.levelCounts[3] || 0, stats.levelCounts[4] || 0, stats.levelCounts[5] || 0,
      npaBlacklist.size, openPhishList.size, '3.0'
    ]);
    
    lastDailySummaryDate = today;
    console.log(`[V2-07] 每日摘要已儲存：${stats.todayDate}`);
  } catch (err) {
    console.error('[V2-07] 每日摘要儲存失敗：', err.message);
  }
}

// 每 5 分鐘嘗試寫入一次（含日切換偵測）
setInterval(saveDailySummary, 5 * 60 * 1000);
// 啟動後 30 秒先寫一次
setTimeout(saveDailySummary, 30 * 1000);

// 公開狀態頁 API（UptimeRobot + 儀表板 + 歷史數據）
app.get('/v1/status', async (req, res) => {
  const startTime = Date.now();
  
  // DB 連線測試
  let dbStatus = 'disconnected';
  try {
    await pool.query('SELECT 1');
    dbStatus = 'connected';
  } catch { dbStatus = 'disconnected (memory mode)'; }
  
  // 取最近 30 天歷史
  let history = [];
  try {
    const histResult = await pool.query(
      `SELECT date, total_checks, total_blocks, unique_ips, level_4, level_5
       FROM daily_stats ORDER BY date DESC LIMIT 30`
    );
    history = histResult.rows;
  } catch {}
  
  const latency = Date.now() - startTime;
  
  res.json({
    status: 'operational',
    version: '3.0.1',
    uptime_seconds: Math.floor(process.uptime()),
    uptime_hours: Math.floor(process.uptime() / 3600),
    latency_ms: latency,
    database: dbStatus,
    database_healthy: dbHealthy,  // P1-07
    engine: {
      rules: {
        bhr: 20,  // BHR1-20
        cc: 23,   // CC1-23
        dom: 6,   // DOM rules
      },
      known_safe: 574,
      blacklists: {
        npa_165: npaBlacklist.size,
        openphish: openPhishList.size,
        majestic: majesticList.size,
      },
      blacklist_health: blacklistHealth,  // P2-05
    },
    today: {
      date: stats.todayDate,
      checks: stats.todayChecks,
      blocks: stats.todayBlocks,
      deep_analyzes: stats.totalDeepAnalyzes,
      protected_users: stats.uniqueIPs.size,
      level_distribution: stats.levelCounts,
    },
    totals: {
      checks: stats.totalChecks,
      blocks: stats.totalBlocks,
    },
    history,
    timestamp: new Date().toISOString(),
  });
});

// UptimeRobot webhook endpoint（接收狀態變更通知）
app.post('/v1/webhook/uptime', (req, res) => {
  const { monitorFriendlyName, alertType, alertDetails } = req.body || {};
  console.log(`[V2-07] UptimeRobot: ${monitorFriendlyName} → ${alertType} | ${alertDetails || ''}`);
  // 未來可接 LINE Notify / Telegram Bot 通知
  res.json({ status: 'ok', received: true });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '3.0.1',
    features: [
      'DOM-Lite 整合（ATK-1）',
      'Unicode Confusable（ATK-3）',
      'BHR9 擴充（ATK-9）',
      'BHR-OV 憑證驗證（V1-09）',
      'L1 DNS TXT 驗證（V1-22）',
      'FP/FN 回報系統',
    ],
    security: {
      cors: 'strict',
      rate_limit: '30/min',
      hotlink_protection: true,
    },
    timestamp: new Date().toISOString(),
    blacklists: {
      npa: npaBlacklist.size,
      openphish: openPhishList.size,
      majestic: majesticList.size
    },
    l1_verified: l1VerifiedDomainsCache.size,
    database: 'PostgreSQL',
    crawler: crawler ? 'enabled' : 'disabled',
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ TrustInt v3.0 威脅分析引擎啟動 port ${PORT}`));
// v2.5 crawler
