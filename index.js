'use strict';

/**
 * TrustInt Crawler Service (V2-02)
 * 獨立 Puppeteer 微服務，與主 API 分離
 * 
 * 部署：Railway 新 service，使用 Dockerfile
 * 通訊：主 API 透過 HTTP 呼叫此服務
 */

const express = require('express');
const puppeteer = require('puppeteer');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 4000;
const AUTH_KEY = process.env.CRAWLER_AUTH_KEY || '';

// ── Puppeteer Browser Pool ──
let browser = null;
const MAX_CONCURRENT = 3;
let activeTasks = 0;

async function getBrowser() {
  if (!browser || !browser.isConnected()) {
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--single-process',
        '--no-zygote',
      ],
      defaultViewport: { width: 1280, height: 800 },
    });
    console.log('[BROWSER] Chromium launched');
  }
  return browser;
}

// 驗證 middleware
function authCheck(req, res, next) {
  if (AUTH_KEY && req.headers['x-crawler-key'] !== AUTH_KEY) {
    return res.status(403).json({ status: 'error', message: 'unauthorized' });
  }
  next();
}

// ══════════════════════════════════════
// P0 語意分析詞庫
// ══════════════════════════════════════
const P0_KEYWORDS = {
  investment_scam: [
    '保證獲利', '穩賺不賠', '日賺', '月賺', '年化報酬', '高報酬', '低風險', '零風險',
    '被動收入', '財富自由', '限時加入', '名額有限', '立即入金', '馬上開戶',
    '入金', '出金', '提幣', '提現', '帶單', '跟單', '日報酬', '翻倍',
    'guaranteed profit', 'risk free', 'passive income',
  ],
  impersonation: [
    '系統升級', '帳號異常', '安全驗證', '重新驗證', '身份驗證', '資料更新',
    '緊急通知', '立即處理', '否則停用', '否則凍結', '24小時內',
    'verify your account', 'confirm your identity', 'suspended',
  ],
  prize_scam: [
    '恭喜中獎', '您已獲得', '免費領取', '限時領取', '點擊領取', '立即領取',
    '禮品卡', 'congratulations', 'you have won', 'claim your prize',
  ],
  romance_scam: [
    '約炮', '一夜情', '私密', '裸聊', '加我', '加賴', '加line', '私聊', '寂寞',
  ],
  loan_scam: [
    '快速貸款', '免審核', '免抵押', '當日放款', '黑名單可貸', '信用不良', '保證過件',
    'instant loan', 'no credit check', 'guaranteed approval',
  ],
  fake_shop: [
    '貨到付款', '限時特價', '售完為止', '免運費', '超低價', '清倉', '下殺', '秒殺',
    '全場', '折扣', '特惠', '搶購',
  ],
};

const SENSITIVE_FORM_FIELDS = [
  'password', 'credit', 'card', 'cvv', 'ssn', 'bank', 'account',
  'routing', '密碼', '信用卡', '銀行', '身份證', '帳號', 'otp', 'pin',
];

// ══════════════════════════════════════
// 爬蟲核心
// ══════════════════════════════════════
async function crawlPage(url, options = {}) {
  const startTime = Date.now();
  const timeout = options.timeout || 20000;
  const screenshot = options.screenshot || false;
  const dualUA = options.dualUA || false;

  if (!url.startsWith('http')) url = 'https://' + url;

  const b = await getBrowser();
  const page = await b.newPage();

  try {
    // 設定 UA
    const desktopUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    await page.setUserAgent(desktopUA);
    await page.setExtraHTTPHeaders({ 'Accept-Language': 'zh-TW,zh;q=0.9,en;q=0.8' });

    // 攔截不必要的資源（加速）
    await page.setRequestInterception(true);
    page.on('request', req => {
      const type = req.resourceType();
      if (['image', 'media', 'font'].includes(type)) req.abort();
      else req.continue();
    });

    // 導航
    const response = await page.goto(url, {
      waitUntil: 'domcontentloaded',
      timeout,
    });

    // 等一下讓 JS 跑完
    await new Promise(r => setTimeout(r, 2000));

    // 提取頁面資訊
    const result = await page.evaluate(() => {
      const title = document.title || '';
      const meta = document.querySelector('meta[name="description"]');
      const description = meta ? meta.getAttribute('content') || '' : '';
      const bodyText = (document.body?.innerText || '').slice(0, 15000);

      // 表單分析
      const forms = document.querySelectorAll('form');
      const formData = [];
      for (const form of forms) {
        const action = form.action || '';
        const inputs = [...form.querySelectorAll('input')].map(inp => ({
          type: inp.type || 'text',
          name: inp.name || '',
          placeholder: inp.placeholder || '',
          autocomplete: inp.autocomplete || '',
        }));
        formData.push({ action, inputs });
      }

      // 所有 input（含 form 外的）
      const allInputs = [...document.querySelectorAll('input')].map(inp => ({
        type: inp.type || 'text',
        name: inp.name || '',
        placeholder: inp.placeholder || '',
      }));

      // 圖片數量 & 文字量
      const imgCount = document.querySelectorAll('img, [style*="background-image"]').length;
      const visibleTextLength = bodyText.replace(/\s+/g, '').length;

      // 外部連結
      const links = [...document.querySelectorAll('a[href]')].map(a => a.href).filter(h => h.startsWith('http'));
      const currentHost = window.location.hostname;
      const externalLinks = links.filter(l => {
        try { return new URL(l).hostname !== currentHost; } catch { return false; }
      });

      // 社交誘導
      const socialKeywords = ['加line', 'line:', 'line id', '加whatsapp', 'whatsapp:', '加telegram', 'tg:', '私訊', '私聊', '加好友'];
      const hasSocialLure = socialKeywords.some(k => bodyText.toLowerCase().includes(k));

      // 倒數計時
      const hasCountdown = !!document.querySelector('[class*="countdown"], [class*="timer"], [id*="countdown"]') ||
        /剩餘\s*\d+\s*(分鐘|小時|秒)/.test(bodyText);

      // 浮動按鈕（假客服）
      const floatingBtns = document.querySelectorAll('[style*="position: fixed"], [style*="position:fixed"], .floating, .chat-widget, [class*="float"]');
      const hasFloatingWidget = floatingBtns.length > 0;

      return {
        title, description, bodyText,
        forms: formData, allInputs,
        imgCount, visibleTextLength,
        externalLinks: externalLinks.slice(0, 20),
        totalLinks: links.length,
        externalLinkCount: externalLinks.length,
        hasSocialLure, hasCountdown, hasFloatingWidget,
      };
    });

    // 截圖（可選）
    let screenshotBase64 = null;
    if (screenshot) {
      const buf = await page.screenshot({ type: 'jpeg', quality: 60, fullPage: false });
      screenshotBase64 = buf.toString('base64');
    }

    // V2-05：雙 UA 掃描（可選）
    let mobileResult = null;
    if (dualUA) {
      const mobileUA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1';
      await page.setUserAgent(mobileUA);
      await page.setViewport({ width: 375, height: 812 });
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
      await new Promise(r => setTimeout(r, 2000));

      mobileResult = await page.evaluate(() => ({
        title: document.title || '',
        bodyText: (document.body?.innerText || '').slice(0, 5000),
        visibleTextLength: (document.body?.innerText || '').replace(/\s+/g, '').length,
      }));
    }

    const duration = Date.now() - startTime;
    const statusCode = response ? response.status() : null;
    const finalUrl = page.url();

    await page.close();

    return {
      success: true,
      url, finalUrl, statusCode,
      ...result,
      screenshot: screenshotBase64,
      mobileResult,
      duration_ms: duration,
    };

  } catch (err) {
    await page.close().catch(() => {});
    return {
      success: false,
      url,
      error: err.message,
      duration_ms: Date.now() - startTime,
    };
  }
}

// ══════════════════════════════════════
// P0 語意分析
// ══════════════════════════════════════
function analyzeP0(crawlResult) {
  if (!crawlResult.success) return { triggered: false, error: crawlResult.error };

  const text = (crawlResult.title + ' ' + crawlResult.description + ' ' + crawlResult.bodyText).toLowerCase();
  const triggered = [];

  for (const [category, keywords] of Object.entries(P0_KEYWORDS)) {
    const matched = keywords.filter(k => text.includes(k.toLowerCase()));
    if (matched.length >= 2) {
      triggered.push({
        code: `P0-${category.toUpperCase()}`,
        category,
        hits: matched.length,
        keywords: matched.slice(0, 5),
        confidence: Math.min(0.5 + matched.length * 0.1, 0.95),
      });
    }
  }

  // 敏感表單
  const sensitiveInputs = [];
  for (const input of (crawlResult.allInputs || [])) {
    const str = (input.name + ' ' + input.placeholder).toLowerCase();
    for (const field of SENSITIVE_FORM_FIELDS) {
      if (str.includes(field)) { sensitiveInputs.push(field); break; }
    }
  }
  if (sensitiveInputs.length >= 2) {
    triggered.push({
      code: 'P0-SENSITIVE-FORM',
      category: 'sensitive_form',
      hits: sensitiveInputs.length,
      fields: sensitiveInputs,
      confidence: Math.min(0.6 + sensitiveInputs.length * 0.1, 0.9),
    });
  }

  // V2-05：UA 差異偵測
  let uaDiff = null;
  if (crawlResult.mobileResult) {
    const desktopLen = crawlResult.visibleTextLength || 0;
    const mobileLen = crawlResult.mobileResult.visibleTextLength || 0;
    const diff = Math.abs(desktopLen - mobileLen) / Math.max(desktopLen, mobileLen, 1);
    if (diff > 0.5) {
      uaDiff = { desktop: desktopLen, mobile: mobileLen, diff_ratio: diff };
      triggered.push({
        code: 'P0-UA-DIFF',
        category: 'ua_cloaking',
        hits: 1,
        confidence: 0.70,
        details: uaDiff,
      });
    }
  }

  return {
    triggered: triggered.length > 0,
    rules: triggered,
    totalScore: triggered.reduce((s, t) => s + t.hits, 0),
    recommendedLevel: triggered.length >= 2 ? 5 : (triggered.length === 1 ? 4 : null),
    uaDiff,
    dom: {
      imgCount: crawlResult.imgCount,
      visibleTextLength: crawlResult.visibleTextLength,
      formCount: crawlResult.forms?.length || 0,
      externalLinkCount: crawlResult.externalLinkCount,
      hasSocialLure: crawlResult.hasSocialLure,
      hasCountdown: crawlResult.hasCountdown,
      hasFloatingWidget: crawlResult.hasFloatingWidget,
    },
  };
}

// ══════════════════════════════════════
// API 端點
// ══════════════════════════════════════

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'trustint-crawler',
    version: '1.0',
    browser: browser?.isConnected() ? 'connected' : 'disconnected',
    active_tasks: activeTasks,
    max_concurrent: MAX_CONCURRENT,
    uptime_seconds: Math.floor(process.uptime()),
  });
});

// 完整爬蟲 + P0 分析
app.post('/crawl', authCheck, async (req, res) => {
  const { domain, screenshot, dualUA } = req.body;
  if (!domain) return res.status(400).json({ status: 'error', message: 'missing domain' });

  if (activeTasks >= MAX_CONCURRENT) {
    return res.status(429).json({ status: 'error', message: 'too many concurrent tasks' });
  }

  activeTasks++;
  try {
    const crawlResult = await crawlPage(domain, { screenshot, dualUA });
    const p0Result = analyzeP0(crawlResult);

    res.json({
      status: 'ok',
      domain,
      crawl: {
        success: crawlResult.success,
        finalUrl: crawlResult.finalUrl,
        statusCode: crawlResult.statusCode,
        title: crawlResult.title,
        description: crawlResult.description,
        duration_ms: crawlResult.duration_ms,
        error: crawlResult.error,
      },
      p0: p0Result,
      screenshot: crawlResult.screenshot || null,
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  } finally {
    activeTasks--;
  }
});

// 純截圖（V2-04 用）
app.post('/screenshot', authCheck, async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ status: 'error', message: 'missing url' });

  if (activeTasks >= MAX_CONCURRENT) {
    return res.status(429).json({ status: 'error', message: 'too many concurrent tasks' });
  }

  activeTasks++;
  try {
    const b = await getBrowser();
    const page = await b.newPage();
    await page.setViewport({ width: 1280, height: 800 });
    await page.goto(url.startsWith('http') ? url : 'https://' + url, {
      waitUntil: 'networkidle2',
      timeout: 20000,
    });
    await new Promise(r => setTimeout(r, 1000));
    const buf = await page.screenshot({ type: 'jpeg', quality: 70, fullPage: false });
    await page.close();

    res.json({
      status: 'ok',
      screenshot: buf.toString('base64'),
      size: buf.length,
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  } finally {
    activeTasks--;
  }
});

// ── 啟動 ──
app.listen(PORT, async () => {
  console.log(`🕷️ TrustInt Crawler Service v1.0 started on port ${PORT}`);
  // 預熱 browser
  try {
    await getBrowser();
    console.log('✅ Chromium ready');
  } catch (err) {
    console.error('⚠️ Chromium launch failed:', err.message);
  }
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('[CRAWLER] Shutting down...');
  if (browser) await browser.close();
  process.exit(0);
});
