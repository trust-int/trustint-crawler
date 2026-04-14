/**
 * TrustInt V2 爬蟲模組（v3.0 更新）
 * 改為呼叫獨立 Crawler Microservice
 * 不再依賴 Browserless.io
 */

const axios = require('axios');

const CRAWLER_URL = process.env.CRAWLER_URL || 'http://localhost:4000';
const CRAWLER_AUTH_KEY = process.env.CRAWLER_AUTH_KEY || '';

// P3-01：Crawler 併發控制（防止慢速攻擊佔滿所有 worker）
const CRAWLER_MAX_CONCURRENT = 5;
let crawlerActiveCount = 0;

// Circuit Breaker：連續失敗 N 次後暫停，避免雪崩
const circuitBreaker = {
  failures: 0,
  lastFailure: 0,
  threshold: 5,       // 連續失敗 5 次觸發
  cooldownMs: 30000,  // 暫停 30 秒
  isOpen() {
    if (this.failures >= this.threshold) {
      if (Date.now() - this.lastFailure < this.cooldownMs) return true;
      // cooldown 結束，半開狀態，讓一個請求試試
      this.failures = Math.floor(this.threshold / 2);
    }
    return false;
  },
  recordSuccess() { this.failures = 0; },
  recordFailure() { this.failures++; this.lastFailure = Date.now(); },
};

/**
 * 呼叫爬蟲服務進行完整爬蟲 + P0 分析
 * P3-01：timeout 從 30s 降到 15s，加入併發上限
 */
async function crawlAndAnalyze(domain, options = {}) {
  // Circuit Breaker 檢查
  if (circuitBreaker.isOpen()) {
    console.log(`[CRAWLER] Circuit breaker OPEN（連續 ${circuitBreaker.failures} 次失敗），跳過：${domain}`);
    return { success: false, domain, error: 'circuit_breaker_open', p0: { triggered: false } };
  }

  // 併發控制
  if (crawlerActiveCount >= CRAWLER_MAX_CONCURRENT) {
    console.log(`[CRAWLER] 併發上限（${CRAWLER_MAX_CONCURRENT}），跳過：${domain}`);
    return { success: false, domain, error: 'concurrent_limit', p0: { triggered: false } };
  }
  crawlerActiveCount++;
  
  console.log(`[CRAWLER] 呼叫爬蟲服務：${domain}（active: ${crawlerActiveCount}）`);
  
  try {
    const res = await axios.post(`${CRAWLER_URL}/crawl`, {
      domain,
      screenshot: options.screenshot || false,
      dualUA: options.dualUA || false,
    }, {
      timeout: 15000,  // P3-01：從 30s 降到 15s
      headers: {
        'Content-Type': 'application/json',
        'x-crawler-key': CRAWLER_AUTH_KEY,
      },
    });

    const data = res.data;
    
    if (data.status !== 'ok') {
      circuitBreaker.recordFailure();
      console.log(`[CRAWLER] 爬蟲服務回傳錯誤：${data.message}`);
      return { success: false, domain, error: data.message, p0: { triggered: false } };
    }

    circuitBreaker.recordSuccess();
    console.log(`[CRAWLER] 爬蟲成功：${domain} | ${data.crawl.duration_ms}ms | 標題：${(data.crawl.title || '').slice(0, 50)}`);
    
    if (data.p0.triggered) {
      console.log(`[CRAWLER] ⚠️ P0 觸發：${domain} | ${data.p0.rules.map(r => r.code).join(', ')}`);
    }

    return {
      success: data.crawl.success,
      domain,
      crawl: data.crawl,
      p0: data.p0,
      screenshot: data.screenshot,
    };

  } catch (err) {
    const errMsg = err.response?.data?.message || err.message;
    circuitBreaker.recordFailure();
    console.log(`[CRAWLER] 爬蟲服務連線失敗：${errMsg}（failures: ${circuitBreaker.failures}）`);
    return { success: false, domain, error: errMsg, p0: { triggered: false } };
  } finally {
    crawlerActiveCount--;
  }
}

/**
 * 截圖（V2-04 用）
 */
async function takeScreenshot(url) {
  try {
    const res = await axios.post(`${CRAWLER_URL}/screenshot`, { url }, {
      timeout: 25000,
      headers: {
        'Content-Type': 'application/json',
        'x-crawler-key': CRAWLER_AUTH_KEY,
      },
    });
    return res.data;
  } catch (err) {
    return { status: 'error', message: err.message };
  }
}

/**
 * 檢查爬蟲服務健康狀態
 */
async function checkHealth() {
  try {
    const res = await axios.get(`${CRAWLER_URL}/health`, { timeout: 5000 });
    return res.data;
  } catch {
    return { status: 'error', browser: 'unreachable' };
  }
}

/**
 * V2-01：視覺相似度比對
 */
async function visualMatch(domain) {
  try {
    const res = await axios.post(`${CRAWLER_URL}/visual-match`, { domain }, {
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'x-crawler-key': CRAWLER_AUTH_KEY,
      },
    });
    const data = res.data;
    if (data.match) {
      console.log(`[V2-01] 視覺比對命中：${domain} 疑似仿冒 ${data.match.brand}（相似度 ${data.match.similarity}%）`);
    }
    return data;
  } catch (err) {
    return { status: 'error', match: null, message: err.message };
  }
}

module.exports = {
  crawlAndAnalyze,
  takeScreenshot,
  visualMatch,
  checkHealth,
};
