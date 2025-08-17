# Netlify 密码保护网站示例

通过 Netlify Functions 和环境变量实现的免费密码保护网站方案，全网站加密，密码不写在代码中。

## 功能特点

- 密码保护所有 `/src` 目录下的页面
- 支持登录/登出功能
- 保护期为24小时（无需重复登录）
- 开发环境兼容HTTP，生产环境强制HTTPS

## 部署步骤

1. 将代码推送到 GitHub 仓库。

2. 在 Netlify 导入仓库并部署。

3. 在 Netlify 项目设置中添加环境变量：
   - `SITE_PASSWORD`：访问密码
   - `COOKIE_SECRET`：随机字符串（用于加密 Cookie）

4. 访问网站域名，输入密码即可访问受保护内容。

## 目录结构说明

- `public/`：存放登录页面和静态资源
  - `login.html`：登录页面
  - `css/`：样式表目录
- `src/`：存放受保护的页面
  - `index.html`：受保护的首页
  - `about.html`：受保护的关于页
- `functions/`：Netlify 函数
  - `auth.js`：处理认证逻辑