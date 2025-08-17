const { createHmac, timingSafeEqual, createHash } = require('crypto');
const fs = require('fs');
const path = require('path');

// 简单的内存存储用于速率限制（在生产环境中应使用Redis等外部存储）
const rateLimitStore = new Map();

// 速率限制配置
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15分钟
const RATE_LIMIT_MAX_ATTEMPTS = 5; // 最大尝试次数

// 生成Cookie，根据环境动态设置Secure标志
const generateCookie = (secret) => {
  const timestamp = Date.now();
  const hash = createHmac('sha256', secret)
    .update(timestamp.toString())
    .digest('hex');
  const isProduction = process.env.NODE_ENV === 'production';
  const secureFlag = isProduction ? 'Secure;' : '';
  // 改进：使用SameSite=Strict提供更好的CSRF保护
  return `auth=${timestamp}-${hash}; Path=/; HttpOnly; ${secureFlag} SameSite=Strict; Max-Age=86400`;
};

// 验证Cookie有效性
const validateCookie = (cookie, secret) => {
  if (!cookie) return false;
  const [timestamp, hash] = cookie.split('-');
  const validHash = createHmac('sha256', secret)
    .update(timestamp)
    .digest('hex');
  
  // 使用恒定时间比较防止时序攻击
  try {
    const hashBuffer = Buffer.from(hash, 'hex');
    const validHashBuffer = Buffer.from(validHash, 'hex');
    
    // 确保缓冲区长度相同
    if (hashBuffer.length !== validHashBuffer.length) {
      return false;
    }
    
    return timingSafeEqual(hashBuffer, validHashBuffer) && (Date.now() - timestamp) < 86400000;
  } catch (err) {
    return false;
  }
};

// 恒定时间密码比较函数
const timingSafePasswordCompare = (password, expectedPassword) => {
  try {
    // 使用HMAC比较防止时序攻击
    const key = 'password-comparison'; // 在生产环境中应使用更安全的密钥
    const passwordHash = createHmac('sha256', key).update(password).digest('hex');
    const expectedPasswordHash = createHmac('sha256', key).update(expectedPassword).digest('hex');
    
    const passwordBuffer = Buffer.from(passwordHash, 'hex');
    const expectedBuffer = Buffer.from(expectedPasswordHash, 'hex');
    
    // 确保缓冲区长度相同
    if (passwordBuffer.length !== expectedBuffer.length) {
      return false;
    }
    
    return timingSafeEqual(passwordBuffer, expectedBuffer);
  } catch (err) {
    return false;
  }
};

// 检查速率限制
const checkRateLimit = (ip) => {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;
  
  // 清理过期记录
  if (rateLimitStore.has(ip)) {
    const attempts = rateLimitStore.get(ip).filter(timestamp => timestamp > windowStart);
    rateLimitStore.set(ip, attempts);
  } else {
    rateLimitStore.set(ip, []);
  }
  
  const attempts = rateLimitStore.get(ip);
  return attempts.length < RATE_LIMIT_MAX_ATTEMPTS;
};

// 记录登录尝试
const recordLoginAttempt = (ip) => {
  const now = Date.now();
  if (rateLimitStore.has(ip)) {
    const attempts = rateLimitStore.get(ip);
    attempts.push(now);
    rateLimitStore.set(ip, attempts);
  } else {
    rateLimitStore.set(ip, [now]);
  }
};

// 读取并返回受保护的页面内容
const getProtectedPage = (requestedPath) => {
  try {
    // 构建文件路径，注意public和src目录的映射关系
    const fullPath = path.join(__dirname, '..', requestedPath);
    const content = fs.readFileSync(fullPath, 'utf8');
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'text/html' },
      body: content
    };
  } catch (err) {
    return { 
      statusCode: 404, 
      headers: { 'Content-Type': 'text/html' },
      body: '<h1>页面不存在</h1><p><a href="/src/index.html">返回首页</a></p>' 
    };
  }
};

exports.handler = async (event, context) => {
  const SITE_PASSWORD = process.env.SITE_PASSWORD;
  const COOKIE_SECRET = process.env.COOKIE_SECRET;

  // 改进：返回通用错误消息而不是透露配置详情
  if (!SITE_PASSWORD || !COOKIE_SECRET) {
    return { statusCode: 500, body: '服务器暂时不可用，请稍后再试' };
  }

  // 获取客户端IP用于速率限制
  const clientIP = event.headers['x-forwarded-for'] || event.headers['x-nf-client-connection-ip'] || 'unknown';

  // 处理登录请求
  if (event.httpMethod === 'POST') {
    // 检查速率限制
    if (!checkRateLimit(clientIP)) {
      return { 
        statusCode: 429, 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          success: false, 
          message: '尝试次数过多，请15分钟后再试' 
        }) 
      };
    }
    
    const { password } = JSON.parse(event.body || '{}');
    
    // 记录登录尝试
    recordLoginAttempt(clientIP);
    
    // 使用恒定时间比较防止时序攻击
    if (timingSafePasswordCompare(password, SITE_PASSWORD)) {
      return {
        statusCode: 200,
        headers: { 'Set-Cookie': generateCookie(COOKIE_SECRET) },
        body: JSON.stringify({ success: true })
      };
    } else {
      return { 
        statusCode: 401, 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          success: false, 
          message: '密码错误' 
        }) 
      };
    }
  }

  // 处理登出请求
  if (event.httpMethod === 'DELETE') {
    return {
      statusCode: 200,
      headers: { 
        'Set-Cookie': 'auth=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ success: true })
    };
  }

  // 处理受保护页面的GET请求
  if (event.httpMethod === 'GET') {
    const cookie = event.headers.cookie?.split('; ')
      .find(c => c.startsWith('auth='))
      ?.split('=')[1];

    if (validateCookie(cookie, COOKIE_SECRET)) {
      // 请求的是登出页面，直接清除Cookie并跳转登录页
      if (event.path === '/logout') {
        return {
          statusCode: 302,
          headers: { 
            'Set-Cookie': 'auth=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
            'Location': '/login.html'
          }
        };
      }
      // 返回请求的受保护页面
      return getProtectedPage(event.path);
    } else {
      // 未验证通过，跳转到登录页
      return {
        statusCode: 302,
        headers: { Location: '/login.html' }
      };
    }
  }

  return { statusCode: 405, body: '方法不支持' };
};