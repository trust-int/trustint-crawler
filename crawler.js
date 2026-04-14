/**
 * TrustInt V2 爬蟲模組（v3.0 更新）
 * 改為呼叫獨立 Crawler Microservice
 * 不再依賴 Browserless.io
 */

const axios = require('axios');

const CRAWLER_URL = process.env.CRAWLER_URL || 'http://localhost:4000';
const CRAWLER_AUTH_KEY = process.env.CRAWLER_AUTH_KEY || '';

/**
 * 呼叫爬蟲服務進行完整爬蟲 + P0 分析
 */
async function crawlAndAnalyze(domain, options = {}) {
  console.log(`[CRAWLER] 呼叫爬蟲服務：${domain}`);
  
  try {
    const res = await axios.post(`${CRAWLER_URL}/crawl`, {
      domain,
      screenshot: options.screenshot || false,
      dualUA: options.dualUA || false,
    }, {
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'x-crawler-key': CRAWLER_AUTH_KEY,
      },
    });

    const data = res.data;
    
    if (data.status !== 'ok') {
      console.log(`[CRAWLER] 爬蟲服務回傳錯誤：${data.message}`);
      return { success: false, domain, error: data.message, p0: { triggered: false } };
    }

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
    console.log(`[CRAWLER] 爬蟲服務連線失敗：${errMsg}`);
    return { success: false, domain, error: errMsg, p0: { triggered: false } };
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
