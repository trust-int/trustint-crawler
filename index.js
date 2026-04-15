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
    // v3.0：假 Google/Apple 中獎
    '隨機選中', '被選中', '幸運用戶', '幸運訪客', '第.*位訪客',
    'randomly selected', 'lucky visitor', 'lucky winner', 'selected winner',
    '贏得 iphone', '贏得iphone', 'win a iphone', 'win an iphone',
    '贏得 samsung', 'win a samsung', 'win a macbook',
    'google reward', 'google prize', 'apple reward',
    '問卷調查.*獎', '填問卷.*獎品', '答題.*獎', 'survey.*reward',
    '獨家優惠', '專屬獎勵', '會員獎勵',
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
  // v3.0 新增：假客服/假技術支援
  fake_support: [
    '您的電腦已感染', '您的裝置已被入侵', '立即撥打', '技術支援',
    'your computer has been compromised', 'call microsoft', 'virus alert',
    'trojan detected', '木馬', '已被鎖定', '已被加密',
  ],
  // v3.0 新增：殺豬盤特徵
  pig_butchering: [
    '老師帶單', '分析師', '內部消息', '穩定獲利', '群組', '飆股',
    '加入我們', '跟著操作', '百分百', '翻倍賺',
  ],
  // v3.0 新增：不知名投資平台
  fake_investment_platform: [
    '開戶即送', '註冊獎金', '首存優惠', '入金獎勵', '模擬交易',
    '槓桿', '合約交易', 'leverage', 'margin', '期權',
    '實盤', '實名認證.*入金', 'kyc.*deposit', '充值',
    '最低入金', 'minimum deposit', '出金手續費', '提現手續費',
  ],
  // v3.0 新增：假虛擬貨幣交易所
  fake_crypto_exchange: [
    'usdt', '泰達幣', '比特幣', '以太幣', 'bitcoin', 'ethereum',
    '幣幣交易', '法幣交易', 'spot trading', 'futures trading',
    '錢包地址', 'wallet address', '提幣地址', '充幣',
    '挖礦收益', 'mining reward', 'staking reward', '質押',
    'defi', 'airdrop', '空投獎勵', 'liquidity mining',
  ],
  // v3.0 新增：感情詐騙平台（交友/聊天/禮包）
  romance_platform: [
    '聊天室', '私聊', '私訊', '視訊聊天', '語音聊天',
    '禮物', '禮包', '鑽石', '金幣', '虛擬禮物', '送禮',
    '充值.*鑽石', '購買.*禮包', '儲值.*金幣',
    '配對', '附近的人', '交友', '約會', 'match', 'dating',
    '會員升級', 'vip', '高級會員', 'premium member',
    '解鎖', '查看照片', '解鎖聊天', '開通',
  ],
  // v3.0：二次詐騙（Recovery Scam）— 騙已經被騙過的人
  recovery_scam: [
    '資金追回', '追回損失', '駭客團隊', '專業追款', '凍結資金', '解凍金',
    '保證金', '手續費.*追回', '法務部授權', '金管會授權',
    'fund recovery', 'get your money back', 'recovery expert',
    '資金找回', '協助追回', '退款保證',
  ],
  // v3.0：側載惡意軟體（APK/EXE 下載陷阱）
  sideloading: [
    '下載 app', '立即下載', '安裝 app', '點擊安裝',
    'download app', 'install now', 'click to install',
    '企業版描述檔', '信任此開發者', 'trust this developer',
  ],
  // v3.0：帳戶凍結恐嚇
  account_freeze: [
    '帳戶異常', '帳號被鎖', '帳戶凍結', '帳號停用', '限期處理',
    '否則永久', '逾期將', '未驗證將',
    'account locked', 'account suspended', 'verify immediately',
    'will be terminated', 'permanently disabled',
  ],
};

const SENSITIVE_FORM_FIELDS = [
  'password', 'credit', 'card', 'cvv', 'ssn', 'bank', 'account',
  'routing', '密碼', '信用卡', '銀行', '身份證', '帳號', 'otp', 'pin',
];

// v3.0：付款頁面偵測關鍵字（非白名單站有這些 = 高度警戒）
const PAYMENT_INDICATORS = {
  // 付款表單欄位
  form_fields: [
    'card-number', 'cardnumber', 'cc-number', 'credit-card',
    'card-holder', 'cardholder', 'card-name',
    'expiry', 'exp-date', 'exp-month', 'exp-year',
    'cvv', 'cvc', 'security-code', 'card-code',
    '卡號', '持卡人', '有效期', '安全碼',
  ],
  // 付款相關文字
  page_text: [
    '信用卡付款', '線上付款', '立即付款', '確認付款', '提交訂單',
    'pay now', 'submit payment', 'credit card payment', 'checkout',
    'billing address', '帳單地址', '付款資訊', 'payment info',
    '訂單金額', 'order total', 'amount due',
  ],
  // 第三方支付（合法的）
  legit_payment: [
    'stripe.com', 'paypal.com', 'ecpay.com.tw', 'newebpay.com',
    'tappaysdk', 'tappay', 'braintree', 'square',
  ],
};

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

      // ── v3.0 新增偵測 ──

      // 法律條款檢查：有沒有 privacy policy / terms 頁面
      const allLinks = [...document.querySelectorAll('a')].map(a => ({
        href: (a.href || '').toLowerCase(),
        text: (a.textContent || '').toLowerCase(),
      }));
      const hasPrivacyPage = allLinks.some(a =>
        a.href.includes('privacy') || a.href.includes('隱私') ||
        a.text.includes('隱私') || a.text.includes('privacy'));
      const hasTermsPage = allLinks.some(a =>
        a.href.includes('terms') || a.href.includes('tos') ||
        a.href.includes('條款') || a.href.includes('服務條款') ||
        a.text.includes('條款') || a.text.includes('terms'));
      const hasAboutPage = allLinks.some(a =>
        a.href.includes('about') || a.href.includes('關於') ||
        a.text.includes('關於我們') || a.text.includes('about'));
      const hasContactPage = allLinks.some(a =>
        a.href.includes('contact') || a.href.includes('聯絡') ||
        a.text.includes('聯絡') || a.text.includes('contact'));

      // 頁面品質分析
      const cssLinks = document.querySelectorAll('link[rel="stylesheet"]').length;
      const inlineStyles = document.querySelectorAll('[style]').length;
      const hasViewport = !!document.querySelector('meta[name="viewport"]');
      const hasFavicon = !!document.querySelector('link[rel="icon"], link[rel="shortcut icon"]');
      const scriptCount = document.querySelectorAll('script').length;
      const brokenImages = [...document.querySelectorAll('img')].filter(img => !img.complete || img.naturalWidth === 0).length;

      // 彈窗/下載偵測
      const bodyLower = bodyText.toLowerCase();
      const hasDownloadPrompt = bodyLower.includes('下載') && (bodyLower.includes('病毒') || bodyLower.includes('中毒') || bodyLower.includes('感染'));
      const hasFakeAlert = bodyLower.includes('您的裝置') || bodyLower.includes('您的手機') || bodyLower.includes('your device') || bodyLower.includes('virus detected');
      const hasUrgency = bodyLower.includes('立即') && (bodyLower.includes('處理') || bodyLower.includes('更新') || bodyLower.includes('驗證'));

      // HTTPS 檢查
      const isHttps = window.location.protocol === 'https:';

      // 頁面語言混亂（中文站夾雜大量簡體或亂碼）
      const hasSimplifiedChinese = /[\u4e00-\u9fff]/.test(bodyText) && (bodyText.includes('确认') || bodyText.includes('开户') || bodyText.includes('银行'));
      
      // 重複內容偵測（同一段文字出現多次 = 低品質）
      const paragraphs = bodyText.split('\n').filter(p => p.trim().length > 20);
      const uniqueParagraphs = new Set(paragraphs.map(p => p.trim()));
      const duplicateRatio = paragraphs.length > 0 ? 1 - (uniqueParagraphs.size / paragraphs.length) : 0;

      // ── v3.0：公司資訊偵測 ──
      const hasCompanyName = /股份有限公司|有限公司|公司|Co\.,?\s*Ltd|Corp|Inc|LLC/i.test(bodyText);
      const hasPhoneNumber = /(\+?886|0[2-9])\s*-?\s*\d{4}\s*-?\s*\d{4}|\d{2,4}-\d{3,4}-\d{3,4}|客服電話|服務電話|service.*phone|customer.*service/i.test(bodyText);
      const hasPhysicalAddress = /市.*區.*路|市.*區.*街|縣.*鄉.*路|縣.*鎮.*路|樓|號|\d+\s*(floor|F)|address/i.test(bodyText);
      const hasEmail = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(bodyText);
      const hasTaxId = /統一編號|統編|VAT|tax.?id/i.test(bodyText);

      // ── v3.0：敏感資料索取偵測 ──
      const allInputsDeep = [...document.querySelectorAll('input, select, textarea')].map(el => ({
        tag: el.tagName.toLowerCase(),
        type: (el.type || '').toLowerCase(),
        name: (el.name || '').toLowerCase(),
        placeholder: (el.placeholder || '').toLowerCase(),
        label: el.labels?.[0]?.textContent?.toLowerCase() || '',
        autocomplete: (el.autocomplete || '').toLowerCase(),
      }));
      
      const sensitiveFields = {
        credit_card: [],
        id_number: [],
        otp_code: [],
        bank_account: [],
        password: [],
      };

      for (const inp of allInputsDeep) {
        const combined = inp.name + ' ' + inp.placeholder + ' ' + inp.label + ' ' + inp.autocomplete;
        
        if (/credit|card.?number|卡號|信用卡|visa|mastercard|cc.?num/i.test(combined) ||
            /cvv|cvc|安全碼|驗證碼.*卡/i.test(combined) ||
            /exp.*date|有效期|到期/i.test(combined)) {
          sensitiveFields.credit_card.push(combined.trim().slice(0, 50));
        }
        if (/身分證|身份證|id.?number|national.?id|居留證|護照|passport/i.test(combined)) {
          sensitiveFields.id_number.push(combined.trim().slice(0, 50));
        }
        if (/otp|驗證碼|verification.?code|sms.?code|簡訊碼|動態密碼/i.test(combined) && 
            !/autocomplete/.test(combined)) {
          sensitiveFields.otp_code.push(combined.trim().slice(0, 50));
        }
        if (/bank.?account|帳號|銀行|routing|匯款/i.test(combined) && 
            !/login|登入|email/.test(combined)) {
          sensitiveFields.bank_account.push(combined.trim().slice(0, 50));
        }
        if (/password|密碼|passcode/i.test(combined) && inp.type !== 'password') {
          // password type 的 input 是正常的登入，但 text type 要求輸入密碼才可疑
          sensitiveFields.password.push(combined.trim().slice(0, 50));
        }
      }

      const sensitiveFieldCount = Object.values(sensitiveFields).reduce((s, arr) => s + arr.length, 0);
      const hasSensitiveDataRequest = sensitiveFieldCount >= 2;

      // ── v3.0：付款頁面偵測 ──
      // 偵測 input 是否有信用卡相關欄位
      const paymentFormFields = [
        'card-number', 'cardnumber', 'cc-number', 'credit-card',
        'card-holder', 'cardholder', 'card-name',
        'expiry', 'exp-date', 'exp-month', 'exp-year',
        'cvv', 'cvc', 'security-code', 'card-code',
        '卡號', '持卡人', '有效期', '安全碼',
      ];
      const paymentTextKeywords = [
        '信用卡付款', '線上付款', '立即付款', '確認付款', '提交訂單',
        'pay now', 'submit payment', 'credit card payment', 'checkout',
        '付款資訊', 'payment info', '訂單金額', 'order total',
        '儲值', '充值', '購買點數', '購買鑽石', '購買金幣',
        '購買禮包', '加值', 'top up', 'recharge',
      ];

      let paymentFieldCount = 0;
      for (const inp of allInputsDeep) {
        const combined = inp.name + ' ' + inp.placeholder + ' ' + inp.label + ' ' + inp.autocomplete;
        if (paymentFormFields.some(k => combined.includes(k))) paymentFieldCount++;
      }

      const paymentTextHits = paymentTextKeywords.filter(k => bodyLower.includes(k)).length;

      // 檢查是否使用合法第三方支付
      const pageHtml = document.documentElement.outerHTML.toLowerCase();
      const hasLegitPayment = ['stripe.com', 'paypal.com', 'ecpay.com.tw', 'newebpay.com',
        'tappaysdk', 'tappay', 'braintree', 'square'].some(p => pageHtml.includes(p));

      const hasPaymentPage = paymentFieldCount >= 2 || paymentTextHits >= 2;

      // ── v3.0：聊天室偵測 ──
      const chatIndicators = [
        'chat', 'chatroom', 'message', 'inbox', '聊天', '訊息', '私訊',
        'websocket', 'socket.io', 'firebase',
      ];
      const hasChatFeature = chatIndicators.some(k => pageHtml.includes(k));

      // ── v3.0：虛擬貨幣/投資平台特徵 ──
      const cryptoIndicators = ['usdt', 'btc', 'eth', 'bitcoin', 'ethereum', '比特幣', '以太幣',
        '幣幣', '合約交易', 'spot', 'futures', 'k線', 'k-line', 'candlestick',
        '交易對', 'trading pair', '錢包', 'wallet'];
      const cryptoHits = cryptoIndicators.filter(k => bodyLower.includes(k)).length;
      const hasCryptoFeature = cryptoHits >= 3;

      const investmentIndicators = ['開戶', '入金', '出金', '槓桿', 'leverage', '保證金',
        'margin', '實盤', '模擬盤', '跟單', '帶單', 'roi', '年化', '日報酬'];
      const investmentHits = investmentIndicators.filter(k => bodyLower.includes(k)).length;
      const hasInvestmentFeature = investmentHits >= 3;

      return {
        title, description, bodyText,
        forms: formData, allInputs,
        imgCount, visibleTextLength,
        externalLinks: externalLinks.slice(0, 20),
        totalLinks: links.length,
        externalLinkCount: externalLinks.length,
        hasSocialLure, hasCountdown, hasFloatingWidget,
        legalPages: { hasPrivacyPage, hasTermsPage, hasAboutPage, hasContactPage },
        pageQuality: {
          cssLinks, inlineStyles, hasViewport, hasFavicon,
          scriptCount, brokenImages, duplicateRatio: +duplicateRatio.toFixed(2),
        },
        threats: {
          hasDownloadPrompt, hasFakeAlert, hasUrgency, isHttps, hasSimplifiedChinese,
        },
        companyInfo: {
          hasCompanyName, hasPhoneNumber, hasPhysicalAddress, hasEmail, hasTaxId,
        },
        sensitiveDataRequest: {
          hasSensitiveDataRequest,
          totalSensitiveFields: sensitiveFieldCount,
          fields: sensitiveFields,
        },
        // v3.0 付款/平台偵測
        paymentDetection: {
          hasPaymentPage,
          paymentFieldCount,
          paymentTextHits,
          hasLegitPayment,
        },
        platformDetection: {
          hasChatFeature,
          hasCryptoFeature, cryptoHits,
          hasInvestmentFeature, investmentHits,
        },

        // ── v3.0 BHR 強因子偵測 ──

        // 孤島網頁偵測：連結有超過 50% 指向 # 或 javascript:void
        hollowShell: (() => {
          const allAnchors = [...document.querySelectorAll('a[href]')];
          if (allAnchors.length < 3) return { isHollow: false, total: allAnchors.length, deadCount: 0 };
          const deadLinks = allAnchors.filter(a => {
            const h = a.getAttribute('href') || '';
            return h === '#' || h === '' || h.startsWith('javascript:') || h === window.location.href || h === window.location.pathname;
          });
          const ratio = deadLinks.length / allAnchors.length;
          return { isHollow: ratio > 0.5, total: allAnchors.length, deadCount: deadLinks.length, ratio: +ratio.toFixed(2) };
        })(),

        // 右鍵禁用 / 防分析腳本偵測
        antiAnalysis: (() => {
          const html = document.documentElement.outerHTML.toLowerCase();
          const hasDisableRightClick = html.includes('oncontextmenu') && (html.includes('return false') || html.includes('preventdefault'));
          const hasDisableSelect = html.includes('onselectstart') || html.includes('user-select: none') || html.includes('user-select:none');
          const hasDebuggerTrap = html.includes('debugger;') || html.includes('setinterval') && html.includes('debugger');
          const hasDevToolsDetect = html.includes('devtools') || html.includes('firebug');
          return { hasDisableRightClick, hasDisableSelect, hasDebuggerTrap, hasDevToolsDetect };
        })(),

        // APK/EXE 下載連結偵測
        sideloadLinks: (() => {
          const dangerousExtensions = ['.apk', '.exe', '.msi', '.dmg', '.ipa', '.mobileprovision'];
          const links = [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href') || '');
          const found = links.filter(h => dangerousExtensions.some(ext => h.toLowerCase().endsWith(ext)));
          return { hasSideload: found.length > 0, count: found.length, urls: found.slice(0, 3) };
        })(),

        // 私鑰/助記詞索取（直接 L5 kill switch）
        seedPhraseRequest: (() => {
          const allInputsCheck = [...document.querySelectorAll('input, textarea')];
          const combined = allInputsCheck.map(el => 
            (el.name + ' ' + el.placeholder + ' ' + (el.labels?.[0]?.textContent || '')).toLowerCase()
          ).join(' ');
          const hasSeedPhrase = /seed.?phrase|助記詞|mnemonic|private.?key|私鑰|recovery.?phrase|secret.?key/.test(combined);
          const bodyCheck = bodyLower;
          const bodyHasSeed = /請輸入.*助記詞|enter.*seed.?phrase|請輸入.*私鑰|enter.*private.?key|12.*words|24.*words/.test(bodyCheck);
          return { detected: hasSeedPhrase || bodyHasSeed, inForm: hasSeedPhrase, inBody: bodyHasSeed };
        })(),
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

    // v3.0：轉址偵測（JS redirect + HTTP redirect）
    let redirectInfo = null;
    try {
      const originalHost = new URL(url).hostname.toLowerCase();
      const finalHost = new URL(finalUrl).hostname.toLowerCase();
      if (originalHost !== finalHost) {
        redirectInfo = {
          from: originalHost,
          to: finalHost,
          crossDomain: true,
          finalUrl,
        };
      } else if (url !== finalUrl) {
        redirectInfo = {
          from: url,
          to: finalUrl,
          crossDomain: false,
          finalUrl,
        };
      }
    } catch {}

    await page.close();

    return {
      success: true,
      url, finalUrl, statusCode,
      ...result,
      screenshot: screenshotBase64,
      mobileResult,
      redirectInfo,
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

  // ── v3.0 新增偵測規則 ──

  // 假警告/假病毒偵測
  const threats = crawlResult.threats || {};
  if (threats.hasFakeAlert || threats.hasDownloadPrompt) {
    triggered.push({
      code: 'P0-FAKE-ALERT',
      category: 'fake_alert',
      hits: (threats.hasFakeAlert ? 1 : 0) + (threats.hasDownloadPrompt ? 1 : 0),
      confidence: 0.80,
    });
  }

  // 緊急性話術 + 無法律條款 = 高度可疑
  const legal = crawlResult.legalPages || {};
  const noLegalPages = !legal.hasPrivacyPage && !legal.hasTermsPage && !legal.hasAboutPage;
  if (threats.hasUrgency && noLegalPages) {
    triggered.push({
      code: 'P0-URGENCY-NO-LEGAL',
      category: 'urgency_no_legal',
      hits: 1,
      confidence: 0.70,
    });
  }

  // 頁面品質極差：文字少 + 圖片多 + 無法律條款 + 無 favicon
  const quality = crawlResult.pageQuality || {};
  const textLen = crawlResult.visibleTextLength || 0;
  const imgCnt = crawlResult.imgCount || 0;
  if (textLen < 200 && imgCnt > 5 && noLegalPages && !quality.hasFavicon) {
    triggered.push({
      code: 'P0-LOW-QUALITY',
      category: 'low_quality_page',
      hits: 1,
      confidence: 0.60,
    });
  }

  // 高重複內容（>30%）= 低品質或自動產生
  if (quality.duplicateRatio > 0.30 && textLen > 500) {
    triggered.push({
      code: 'P0-DUPLICATE-CONTENT',
      category: 'duplicate_content',
      hits: 1,
      confidence: 0.55,
    });
  }

  // v3.0：跨域轉址偵測（原始域名 ≠ 最終域名 = 可疑）
  if (crawlResult.redirectInfo && crawlResult.redirectInfo.crossDomain) {
    triggered.push({
      code: 'P0-CROSS-DOMAIN-REDIRECT',
      category: 'cross_domain_redirect',
      hits: 1,
      confidence: 0.65,
      details: crawlResult.redirectInfo,
    });
  }

  // v3.0：無公司資訊 + 要求敏感資料 = 高度可疑
  const company = crawlResult.companyInfo || {};
  const sensitive = crawlResult.sensitiveDataRequest || {};
  const noCompanyInfo = !company.hasCompanyName && !company.hasPhoneNumber && !company.hasPhysicalAddress;
  
  if (sensitive.hasSensitiveDataRequest && noCompanyInfo) {
    triggered.push({
      code: 'P0-SENSITIVE-NO-COMPANY',
      category: 'sensitive_no_company',
      hits: sensitive.totalSensitiveFields,
      confidence: 0.85,
      details: {
        fields: sensitive.fields,
        noCompanyName: !company.hasCompanyName,
        noPhone: !company.hasPhoneNumber,
        noAddress: !company.hasPhysicalAddress,
      },
    });
  }

  // 單獨要求敏感資料（即使有公司資訊，3 個以上敏感欄位也要警告）
  if (sensitive.totalSensitiveFields >= 3) {
    triggered.push({
      code: 'P0-EXCESSIVE-SENSITIVE',
      category: 'excessive_sensitive_fields',
      hits: sensitive.totalSensitiveFields,
      confidence: Math.min(0.6 + sensitive.totalSensitiveFields * 0.08, 0.90),
      details: sensitive.fields,
    });
  }

  // 無公司資訊 + 無法律條款 + 非知名站 = 弱訊號累積
  const legalPages = crawlResult.legalPages || {};
  const noLegal = !legalPages.hasPrivacyPage && !legalPages.hasTermsPage;
  if (noCompanyInfo && noLegal && (crawlResult.visibleTextLength || 0) > 100) {
    triggered.push({
      code: 'P0-NO-IDENTITY',
      category: 'no_identity',
      hits: 1,
      confidence: 0.50,
    });
  }

  // v3.0：非白名單站有付款頁面 + 無合法第三方支付 = 高風險
  const payment = crawlResult.paymentDetection || {};
  if (payment.hasPaymentPage && !payment.hasLegitPayment) {
    triggered.push({
      code: 'P0-UNSAFE-PAYMENT',
      category: 'unsafe_payment',
      hits: payment.paymentFieldCount + payment.paymentTextHits,
      confidence: 0.80,
      details: { paymentFields: payment.paymentFieldCount, textHits: payment.paymentTextHits },
    });
  }

  // 有付款頁面 + 有合法第三方支付 → 降低但仍然提醒
  if (payment.hasPaymentPage && payment.hasLegitPayment) {
    triggered.push({
      code: 'P0-PAYMENT-DETECTED',
      category: 'payment_detected',
      hits: 1,
      confidence: 0.40, // 低信心，因為有合法支付
    });
  }

  // v3.0：不知名虛擬貨幣平台（crypto 特徵多 + 非知名交易所）
  const platform = crawlResult.platformDetection || {};
  if (platform.hasCryptoFeature) {
    triggered.push({
      code: 'P0-UNKNOWN-CRYPTO',
      category: 'unknown_crypto_platform',
      hits: platform.cryptoHits,
      confidence: Math.min(0.5 + platform.cryptoHits * 0.05, 0.85),
    });
  }

  // v3.0：不知名投資平台
  if (platform.hasInvestmentFeature) {
    triggered.push({
      code: 'P0-UNKNOWN-INVESTMENT',
      category: 'unknown_investment_platform',
      hits: platform.investmentHits,
      confidence: Math.min(0.5 + platform.investmentHits * 0.05, 0.85),
    });
  }

  // v3.0：聊天室 + 付款 + 無公司資訊 = 感情詐騙平台特徵
  if (platform.hasChatFeature && payment.hasPaymentPage && noCompanyInfo) {
    triggered.push({
      code: 'P0-ROMANCE-PLATFORM',
      category: 'romance_scam_platform',
      hits: 3,
      confidence: 0.85,
    });
  }

  // ── v3.0 BHR 強因子 P0 規則 ──

  // BHR-21：孤島網頁（Dead-end Links）— 超過 50% 連結是空的
  const hollow = crawlResult.hollowShell || {};
  if (hollow.isHollow && sensitive.hasSensitiveDataRequest) {
    triggered.push({
      code: 'P0-HOLLOW-SHELL',
      category: 'hollow_shell',
      hits: hollow.deadCount,
      confidence: 0.85,
      details: hollow,
    });
  }

  // BHR-22：右鍵禁用 + 金融語意 = 心虛的釣魚站
  const antiA = crawlResult.antiAnalysis || {};
  if ((antiA.hasDisableRightClick || antiA.hasDebuggerTrap) && 
      triggered.some(r => ['investment_scam', 'impersonation', 'fake_crypto_exchange', 'pig_butchering'].includes(r.category))) {
    triggered.push({
      code: 'P0-ANTI-ANALYSIS',
      category: 'anti_analysis',
      hits: 1,
      confidence: 0.75,
    });
  }

  // BHR-23：APK/EXE 下載連結 = 側載惡意軟體
  const sideload = crawlResult.sideloadLinks || {};
  if (sideload.hasSideload) {
    triggered.push({
      code: 'P0-SIDELOAD',
      category: 'sideload_malware',
      hits: sideload.count,
      confidence: 0.90,
      details: { urls: sideload.urls },
    });
  }

  // BHR-24：私鑰/助記詞索取 = 直接 L5（Kill Switch）
  const seedPhrase = crawlResult.seedPhraseRequest || {};
  if (seedPhrase.detected) {
    triggered.push({
      code: 'P0-SEED-PHRASE',
      category: 'seed_phrase_theft',
      hits: 1,
      confidence: 0.99,
    });
  }

  return {
    triggered: triggered.length > 0,
    rules: triggered,
    totalScore: triggered.reduce((s, t) => s + t.hits, 0),
    recommendedLevel: seedPhrase.detected ? 5 : (triggered.length >= 2 ? 5 : (triggered.length === 1 ? 4 : null)),
    uaDiff,
    redirectInfo: crawlResult.redirectInfo || null,
    dom: {
      imgCount: crawlResult.imgCount,
      visibleTextLength: crawlResult.visibleTextLength,
      formCount: crawlResult.forms?.length || 0,
      externalLinkCount: crawlResult.externalLinkCount,
      hasSocialLure: crawlResult.hasSocialLure,
      hasCountdown: crawlResult.hasCountdown,
      hasFloatingWidget: crawlResult.hasFloatingWidget,
    },
    legalPages: crawlResult.legalPages || {},
    pageQuality: crawlResult.pageQuality || {},
    threats: crawlResult.threats || {},
    companyInfo: crawlResult.companyInfo || {},
    sensitiveDataRequest: crawlResult.sensitiveDataRequest || {},
    paymentDetection: crawlResult.paymentDetection || {},
    platformDetection: crawlResult.platformDetection || {},
    hollowShell: crawlResult.hollowShell || {},
    antiAnalysis: crawlResult.antiAnalysis || {},
    sideloadLinks: crawlResult.sideloadLinks || {},
    seedPhraseRequest: crawlResult.seedPhraseRequest || {},
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

// ══════════════════════════════════════
// V2-01：視覺相似度比對（pHash）
// ══════════════════════════════════════

// 品牌截圖 pHash 資料庫（啟動時用爬蟲自動擷取，或用預設 hash）
// hash 格式：64-bit 二進位字串
const BRAND_HASHES = new Map();

// 簡易 pHash 實作：縮小圖片 → 灰階 → DCT → 取中位數 → 生成 hash
async function computePHash(base64Image) {
  try {
    const Jimp = require('jimp');
    const buf = Buffer.from(base64Image, 'base64');
    const img = await Jimp.read(buf);

    // 縮小到 32x32 再取 8x8（模擬 DCT 低頻）
    img.resize(32, 32).greyscale();

    // 取 8x8 左上角（低頻區域）
    const pixels = [];
    for (let y = 0; y < 8; y++) {
      for (let x = 0; x < 8; x++) {
        const color = Jimp.intToRGBA(img.getPixelColor(x, y));
        pixels.push(color.r); // 已經是灰階，RGB 都一樣
      }
    }

    // 計算平均值
    const avg = pixels.reduce((s, p) => s + p, 0) / pixels.length;

    // 生成 hash：大於平均 = 1，小於 = 0
    const hash = pixels.map(p => p >= avg ? '1' : '0').join('');
    return hash;
  } catch (err) {
    console.error('[V2-01] pHash 計算失敗：', err.message);
    return null;
  }
}

// 漢明距離（兩個 hash 之間有多少 bit 不同）
function hammingDistance(hash1, hash2) {
  if (!hash1 || !hash2 || hash1.length !== hash2.length) return 64; // 最大距離
  let dist = 0;
  for (let i = 0; i < hash1.length; i++) {
    if (hash1[i] !== hash2[i]) dist++;
  }
  return dist;
}

// 相似度（0-100%，越高越相似）
function hashSimilarity(hash1, hash2) {
  const dist = hammingDistance(hash1, hash2);
  return Math.round((1 - dist / 64) * 100);
}

// 比對目標 hash 與品牌資料庫
function matchBrandHash(targetHash) {
  if (!targetHash || BRAND_HASHES.size === 0) return null;

  let bestMatch = null;
  let bestSimilarity = 0;

  for (const [brand, data] of BRAND_HASHES) {
    const sim = hashSimilarity(targetHash, data.hash);
    if (sim > bestSimilarity) {
      bestSimilarity = sim;
      bestMatch = { brand, domain: data.domain, similarity: sim };
    }
  }

  // 閾值：75% 以上才算疑似仿冒
  if (bestSimilarity >= 75) return bestMatch;
  return null;
}

// 品牌截圖 + hash 建立（啟動時執行）
async function buildBrandHashes() {
  const brands = [
    { brand: '台灣銀行', domain: 'www.bot.com.tw' },
    { brand: '中國信託', domain: 'www.ctbcbank.com' },
    { brand: '玉山銀行', domain: 'www.esunbank.com.tw' },
    { brand: '國泰世華', domain: 'www.cathaybk.com.tw' },
    { brand: '富邦銀行', domain: 'www.fubon.com' },
    { brand: '台新銀行', domain: 'www.taishinbank.com.tw' },
    { brand: 'LINE', domain: 'line.me' },
    { brand: '蝦皮', domain: 'shopee.tw' },
    { brand: 'momo', domain: 'www.momoshop.com.tw' },
    { brand: 'Google', domain: 'www.google.com' },
    { brand: 'Facebook', domain: 'www.facebook.com' },
    { brand: 'Apple', domain: 'www.apple.com' },
    { brand: 'Microsoft', domain: 'www.microsoft.com' },
    { brand: '中華郵政', domain: 'www.post.gov.tw' },
    { brand: '財政部', domain: 'www.mof.gov.tw' },
    { brand: '健保署', domain: 'www.nhi.gov.tw' },
  ];

  console.log(`[V2-01] 開始建立品牌 hash 資料庫（${brands.length} 個品牌）...`);

  for (const { brand, domain } of brands) {
    try {
      const b = await getBrowser();
      const page = await b.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      await page.goto('https://' + domain, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await new Promise(r => setTimeout(r, 2000));
      const buf = await page.screenshot({ type: 'jpeg', quality: 60, fullPage: false });
      await page.close();

      const hash = await computePHash(buf.toString('base64'));
      if (hash) {
        BRAND_HASHES.set(brand, { domain, hash, capturedAt: new Date().toISOString() });
        console.log(`[V2-01] ✅ ${brand} (${domain}) hash: ${hash.substring(0, 16)}...`);
      }
    } catch (err) {
      console.log(`[V2-01] ⚠️ ${brand} (${domain}) 截圖失敗：${err.message}`);
    }
  }

  console.log(`[V2-01] 品牌 hash 資料庫建立完成：${BRAND_HASHES.size}/${brands.length}`);
}

// 視覺相似度比對 API
app.post('/visual-match', authCheck, async (req, res) => {
  const { domain, screenshot } = req.body;
  if (!domain && !screenshot) {
    return res.status(400).json({ status: 'error', message: 'missing domain or screenshot' });
  }

  if (activeTasks >= MAX_CONCURRENT) {
    return res.status(429).json({ status: 'error', message: 'too many concurrent tasks' });
  }

  activeTasks++;
  try {
    let base64Screenshot = screenshot;

    // 如果沒有提供截圖，自己截
    if (!base64Screenshot && domain) {
      const b = await getBrowser();
      const page = await b.newPage();
      await page.setViewport({ width: 1280, height: 800 });
      const url = domain.startsWith('http') ? domain : 'https://' + domain;
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await new Promise(r => setTimeout(r, 2000));
      const buf = await page.screenshot({ type: 'jpeg', quality: 60, fullPage: false });
      await page.close();
      base64Screenshot = buf.toString('base64');
    }

    // 計算 hash
    const targetHash = await computePHash(base64Screenshot);
    if (!targetHash) {
      return res.json({ status: 'ok', match: null, error: 'hash computation failed' });
    }

    // 比對
    const match = matchBrandHash(targetHash);

    res.json({
      status: 'ok',
      targetHash: targetHash.substring(0, 16) + '...',
      brandDbSize: BRAND_HASHES.size,
      match,
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  } finally {
    activeTasks--;
  }
});

// 查看品牌 hash 資料庫
app.get('/brand-hashes', authCheck, (req, res) => {
  const list = [];
  for (const [brand, data] of BRAND_HASHES) {
    list.push({ brand, domain: data.domain, hashPrefix: data.hash.substring(0, 16), capturedAt: data.capturedAt });
  }
  res.json({ status: 'ok', count: BRAND_HASHES.size, brands: list });
});

// ── 啟動 ──
app.listen(PORT, async () => {
  console.log(`🕷️ TrustInt Crawler Service v1.1 started on port ${PORT}`);
  // 預熱 browser
  try {
    await getBrowser();
    console.log('✅ Chromium ready');
    // 背景建立品牌 hash（不阻塞啟動）
    setTimeout(buildBrandHashes, 5000);
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
