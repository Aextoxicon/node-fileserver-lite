const express = require('express');
const serveIndex = require('serve-index');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;
const os = require('os');
const crypto = require('crypto');

const app = express();
const configPath = './config.json';
let config;
try {
  const configData = fs.readFileSync(configPath, 'utf-8');
  config = JSON.parse(configData);
} catch (err) {
  console.error('加载配置文件失败:', err);
  console.error('请检查 config.json 文件并确保格式正确');
  console.error('现在使用默认配置，上传目录为./uploads，密码Default_Pwd-123，端口9178');
  useDefaultConf();
}

function useDefaultConf() {
  home = os.homedir()
  let uploadDir = path.join(home, 'upload');
  config = {
    uploadDir: uploadDir,
    apiToken: 'Default_Pwd-123',
    port: 9178,
    allowedExts: ['.jpg', '.png', '.gif', '.webp', '.apk', '.zip', '.sh'],
  };
}

const uploadDir = config.uploadDir;
const apiToken = config.apiToken;
const PORT = config.port;
const allowedExts = config.allowedExts;

// 检查上传目录，如果没有则创建
(async () => {
  try {
    await fsp.access(uploadDir);
  } catch {
    fsp.mkdir(uploadDir, { recursive: true, mode: 0o755 }, (err) => {
      if (err) {
        console.error('创建上传目录失败:', err);
      }
    });
  }
})();

// 工具
function generateRandomString(bytes = 6) {
  return crypto.randomBytes(bytes).toString('hex');
}

function sanitizeFilename(name) {
  return name
    .replace(/[/\\?%*:|"<>]/g, '_') // 替换危险字符
    .replace(/\s+/g, '_')           // 空格转下划线
    .replace(/_{2,}/g, '_')         // 合并多个下划线
    .trim()
    .substring(0, 200); // 限制长度
}

// Token
function tokenAuthMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ error: "Authorization format must be 'Bearer <token>'" });
  }

  const token = parts[1];
  if (token !== apiToken) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  next();
}

// Multer
const upload = multer({
  storage: multer.diskStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('仅支持 JPG/PNG/GIF/WebP/APK/ZIP/Shell 脚本文件'));
    }
  },
});

// 上传文件
app.post('/upload', tokenAuthMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: '未选择文件' });
  }

  res.status(202).json({
    message: 'Upload accepted. Processing in background.',
    url: url,
  });

  try {
    async function processFileUpload(file) {
      const originalName = file.originalname;
      const ext = path.extname(originalName).toLowerCase();
      let safeName;

      if (['.apk', '.zip'].includes(ext)) {
        const baseName = path.basename(originalName, ext);
        const cleanBase = sanitizeFilename(baseName);
        safeName = `${cleanBase}${ext}`;
      } else {
        const timestamp = Math.floor(Date.now() / 1000);
        const randomStr = generateRandomString(6);
        safeName = `${timestamp}_${randomStr}${ext}`;
      }

      const savePath = path.join(uploadDir, safeName);
      await fsp.writeFile(savePath, file.buffer);
    }

    const url = `${req.protocol}://${req.get('host')}/${encodeURIComponent(safeName)}`;
    res.json({ url });
  } catch (err) {
    console.error('保存文件失败:', err);
    res.status(500).json({ error: '保存文件失败' });
  }
});

// 下载文件
app.get('/:filename', async (req, res) => {
  const filename = req.params.filename;

  // 严格校验文件名格式
  if (!/^[a-zA-Z0-9._@\-]+$/.test(filename)) {
    return res.status(400).json({ error: '非法文件名' });
  }

  const resolvedPath = path.resolve(uploadDir, filename);
  if (!resolvedPath.startsWith(path.resolve(uploadDir))) {
    return res.status(400).json({ error: '非法文件路径' });
  }

  const filePath = path.join(uploadDir, filename);

  try {
    await fsp.access(filePath);

    // Content-Type
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp',
      '.apk': 'application/vnd.android.package-archive',
      '.zip': 'application/zip',
      '.sh': 'application/x-sh',
    };
    const contentType = mimeTypes[ext] || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);

    res.sendFile(filePath);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return res.status(404).json({ error: '文件不存在' });
    }
    console.error('文件读取错误:', err);
    res.status(500).json({ error: '内部服务器错误' });
  }
});

// 列出文件
app.get('/list', async (req, res) => {
  try {
    const entries = fsp.readdirSync(uploadDir, { withFileTypes: true });
    const files = [];

    for (const entry of entries) {
      if (entry.isFile()) {
        const stat = fsp.statSync(path.join(uploadDir, entry.name));
        files.push({
          filename: entry.name,
          size: stat.size,
        });
      }
    }

    res.json({ files });
  } catch (err) {
    console.error('获取文件列表失败:', err);
    res.status(500).json({ error: '获取文件列表失败' });
  }
});

// Multer 错误处理
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: '文件大小超过限制（APK/ZIP 最大 100MB）' });
    }
    return res.status(400).json({ error: '文件上传错误' });
  }
  next(err);
});

app.use('/', serveIndex(uploadDir, { icons: true, view: 'details' }))

app.listen(PORT, () => {
  console.log(`服务运行在 http://localhost:${PORT}`);
  console.log(`上传目录: ${uploadDir}`);
});
