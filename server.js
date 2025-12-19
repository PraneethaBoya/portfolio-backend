const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const os = require('os');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

const ROOT_DIR = __dirname;
const DEFAULT_DATABASE_PATH = path.join(ROOT_DIR, 'database.json');
const FALLBACK_DATABASE_PATH = path.join(os.tmpdir(), 'portfolio-database.json');
let DATABASE_PATH = process.env.DATABASE_PATH ? path.resolve(process.env.DATABASE_PATH) : DEFAULT_DATABASE_PATH;

const DEFAULT_UPLOADS_DIR = path.join(ROOT_DIR, 'uploads');
const FALLBACK_UPLOADS_DIR = path.join(os.tmpdir(), 'portfolio-uploads');
let UPLOADS_DIR = process.env.UPLOADS_DIR ? path.resolve(process.env.UPLOADS_DIR) : DEFAULT_UPLOADS_DIR;

const corsOrigins = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && (corsOrigins.length === 0 || corsOrigins.includes(origin))) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Vary', 'Origin');
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Headers', 'Content-Type');
        res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    }
    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }
    return next();
});

app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));

const cookieSameSite = (process.env.COOKIE_SAMESITE || (process.env.NODE_ENV === 'production' ? 'none' : 'lax')).toLowerCase();
let cookieSecure = process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production';
if (cookieSameSite === 'none') cookieSecure = true;

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: cookieSameSite,
        secure: cookieSecure
    }
}));

app.get('/', (req, res) => {
    return res.json({ ok: true, message: 'Portfolio CMS API is running.' });
});

const uploadsStaticDirs = Array.from(new Set([UPLOADS_DIR, DEFAULT_UPLOADS_DIR, FALLBACK_UPLOADS_DIR].filter(Boolean)));
uploadsStaticDirs.forEach((dir) => {
    app.use('/uploads', express.static(dir));
});

function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
}

function isValidEmail(email) {
    if (!isNonEmptyString(email)) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

function parseJsonArray(value) {
    if (Array.isArray(value)) return value;
    if (!isNonEmptyString(value)) return [];
    try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
        return [];
    }
}

function sanitizeUploadedFilename(originalName) {
    const rawExt = path.extname(originalName || '').toLowerCase();
    const ext = rawExt && rawExt.length <= 10 ? rawExt : '';
    const rawBase = path.basename(originalName || '', rawExt);
    const base = rawBase
        .toString()
        .trim()
        .replace(/[^a-z0-9\-\_\.\s]/gi, '')
        .replace(/\s+/g, '-')
        .slice(0, 80) || 'file';
    return `${Date.now()}-${base}${ext}`;
}

function createRateLimiter({ windowMs, max }) {
    const store = new Map();
    return (req, res, next) => {
        const key = `${req.ip}`;
        const now = Date.now();
        const current = store.get(key);
        if (!current || now > current.resetAt) {
            store.set(key, { count: 1, resetAt: now + windowMs });
            return next();
        }

        if (current.count >= max) {
            return res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
        }

        current.count += 1;
        store.set(key, current);
        return next();
    };
}

const loginLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 10 });
const contactLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 10 });

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        try {
            if (!fs.existsSync(UPLOADS_DIR)) {
                fs.mkdirSync(UPLOADS_DIR, { recursive: true });
            }
            cb(null, UPLOADS_DIR);
        } catch (err) {
            try {
                UPLOADS_DIR = FALLBACK_UPLOADS_DIR;
                if (!fs.existsSync(UPLOADS_DIR)) {
                    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
                }
                cb(null, UPLOADS_DIR);
            } catch (fallbackErr) {
                cb(fallbackErr);
            }
        }
    },
    filename: (req, file, cb) => {
        cb(null, sanitizeUploadedFilename(file.originalname));
    }
});

const imageFileFilter = (req, file, cb) => {
    if (file && typeof file.mimetype === 'string' && file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        const err = new Error('Invalid file type. Only images are allowed.');
        err.status = 400;
        cb(err);
    }
};

const resumeFileFilter = (req, file, cb) => {
    const isPdf = (file && file.mimetype === 'application/pdf') || (file && typeof file.originalname === 'string' && file.originalname.toLowerCase().endsWith('.pdf'));
    if (isPdf) {
        cb(null, true);
    } else {
        const err = new Error('Invalid file type. Only PDF resumes are allowed.');
        err.status = 400;
        cb(err);
    }
};

const uploadImage = multer({
    storage,
    fileFilter: imageFileFilter,
    limits: { fileSize: 5 * 1024 * 1024 }
});

const uploadResume = multer({
    storage,
    fileFilter: resumeFileFilter,
    limits: { fileSize: 10 * 1024 * 1024 }
});

function ensureDbShape(db) {
    if (!db) return null;
    if (!db.profile) db.profile = {};
    if (!db.profile.resume) db.profile.resume = '';
    if (!Array.isArray(db.skills)) db.skills = [];
    if (!Array.isArray(db.projects)) db.projects = [];
    if (!Array.isArray(db.experience)) db.experience = [];
    if (!Array.isArray(db.blogs)) db.blogs = [];
    if (!Array.isArray(db.education)) db.education = [];
    if (!Array.isArray(db.messages)) db.messages = [];
    return db;
}

function readDatabase() {
    try {
        const data = fs.readFileSync(DATABASE_PATH, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        try {
            if (DATABASE_PATH !== FALLBACK_DATABASE_PATH) {
                const data = fs.readFileSync(FALLBACK_DATABASE_PATH, 'utf8');
                DATABASE_PATH = FALLBACK_DATABASE_PATH;
                return JSON.parse(data);
            }
        } catch (_) {}

        try {
            const seeded = fs.readFileSync(DEFAULT_DATABASE_PATH, 'utf8');
            const parsed = JSON.parse(seeded);
            try {
                fs.writeFileSync(FALLBACK_DATABASE_PATH, JSON.stringify(parsed, null, 2));
                DATABASE_PATH = FALLBACK_DATABASE_PATH;
            } catch (_) {}
            return parsed;
        } catch (_) {}

        console.error('Error reading database:', error);
        return null;
    }
}

function writeDatabase(data) {
    try {
        fs.writeFileSync(DATABASE_PATH, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        try {
            DATABASE_PATH = FALLBACK_DATABASE_PATH;
            fs.writeFileSync(DATABASE_PATH, JSON.stringify(data, null, 2));
            return true;
        } catch (fallbackErr) {
            console.error('Error writing database:', error);
            console.error('Fallback database write failed:', fallbackErr);
            return false;
        }
    }
}

function isAuthenticated(req, res, next) {
    if (req.session.isAuthenticated) {
        next();
    } else {
        res.status(401).json({ error: 'Your session has expired. Please sign in again.' });
    }
}

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!isValidEmail(email) || !isNonEmptyString(password)) {
        return res.status(400).json({ error: 'Please enter a valid email and password.' });
    }

    const expectedEmail = process.env.ADMIN_EMAIL;
    const expectedPassword = process.env.ADMIN_PASSWORD;

    if (!isNonEmptyString(expectedEmail) || !isNonEmptyString(expectedPassword)) {
        return res.status(500).json({ error: 'Admin login isn\'t configured yet. Please set ADMIN_EMAIL and ADMIN_PASSWORD on the server.' });
    }

    const emailOk = email.trim() === expectedEmail.trim();
    const raw = expectedPassword.trim();
    const passwordOk = raw.startsWith('$2') ? await bcrypt.compare(password, raw) : password === raw;

    if (emailOk && passwordOk) {
        req.session.isAuthenticated = true;
        req.session.adminEmail = email;
        return res.json({ success: true, message: 'Signed in successfully.' });
    }

    return res.status(401).json({ error: 'Incorrect email or password.' });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            res.status(500).json({ error: 'Couldn\'t sign you out. Please try again.' });
        } else {
            res.json({ success: true, message: 'Signed out successfully.' });
        }
    });
});

app.get('/api/auth/check', (req, res) => {
    res.json({ isAuthenticated: !!req.session.isAuthenticated });
});

app.get('/api/portfolio', (req, res) => {
    const db = ensureDbShape(readDatabase());
    if (db) {
        res.json({
            profile: db.profile,
            skills: db.skills,
            projects: db.projects,
            experience: db.experience,
            blogs: db.blogs,
            education: db.education
        });
    } else {
        res.status(500).json({ error: 'Couldn\'t load portfolio data right now. Please try again.' });
    }
});

app.get('/api/profile', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    res.json(db.profile);
});

app.put('/api/profile', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    const { twitter, ...rest } = (req && req.body) ? req.body : {};
    db.profile = { ...db.profile, ...rest };
    if (db.profile && Object.prototype.hasOwnProperty.call(db.profile, 'twitter')) {
        delete db.profile.twitter;
    }
    if (writeDatabase(db)) {
        res.json({ success: true, data: db.profile });
    } else {
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

app.post('/api/profile/image', isAuthenticated, uploadImage.single('image'), (req, res) => {
    if (req.file) {
        const db = ensureDbShape(readDatabase());
        db.profile.image = '/uploads/' + req.file.filename;
        if (writeDatabase(db)) {
            res.json({ success: true, imagePath: db.profile.image });
        } else {
            res.status(500).json({ error: 'Failed to update image' });
        }
    } else {
        res.status(400).json({ error: 'No file uploaded' });
    }
});

app.post('/api/profile/resume', isAuthenticated, uploadResume.single('resume'), (req, res) => {
    if (req.file) {
        const db = ensureDbShape(readDatabase());
        db.profile.resume = '/uploads/' + req.file.filename;
        if (writeDatabase(db)) {
            res.json({ success: true, resumePath: db.profile.resume });
        } else {
            res.status(500).json({ error: 'Failed to update resume' });
        }
    } else {
        res.status(400).json({ error: 'No file uploaded' });
    }
});

app.get('/api/resume/download', (req, res) => {
    const db = ensureDbShape(readDatabase());
    if (!db || !db.profile || !db.profile.resume) {
        return res.status(404).json({ error: 'Resume not found' });
    }

    const resumePath = db.profile.resume;
    const relative = resumePath.startsWith('/uploads/') ? resumePath.slice('/uploads/'.length) : resumePath;
    const absolute = path.join(__dirname, 'uploads', relative);

    if (!fs.existsSync(absolute)) {
        return res.status(404).json({ error: 'Resume file not found' });
    }

    const safeName = (db.profile.name || 'resume')
        .toString()
        .trim()
        .replace(/[^a-z0-9\-\_\s]/gi, '')
        .replace(/\s+/g, '-');

    return res.download(absolute, `${safeName}-resume.pdf`);
});

app.get('/api/skills', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    res.json(db.skills);
});

app.post('/api/skills', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    const newSkill = {
        id: Date.now().toString(),
        ...req.body
    };
    db.skills.push(newSkill);
    if (writeDatabase(db)) {
        res.json({ success: true, data: newSkill });
    } else {
        res.status(500).json({ error: 'Failed to add skill' });
    }
});

app.put('/api/skills/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    const index = db.skills.findIndex(s => s.id === req.params.id);
    if (index !== -1) {
        db.skills[index] = { ...db.skills[index], ...req.body };
        if (writeDatabase(db)) {
            res.json({ success: true, data: db.skills[index] });
        } else {
            res.status(500).json({ error: 'Failed to update skill' });
        }
    } else {
        res.status(404).json({ error: 'Skill not found' });
    }
});

app.delete('/api/skills/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    db.skills = db.skills.filter(s => s.id !== req.params.id);
    if (writeDatabase(db)) {
        res.json({ success: true });
    } else {
        res.status(500).json({ error: 'Failed to delete skill' });
    }
});

app.get('/api/projects', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    res.json(db.projects);
});

app.post('/api/projects', isAuthenticated, uploadImage.single('image'), (req, res) => {
    const db = ensureDbShape(readDatabase());
    const newProject = {
        id: Date.now().toString(),
        title: req.body.title,
        description: req.body.description,
        techStack: parseJsonArray(req.body.techStack),
        date: req.body.date,
        image: req.file ? '/uploads/' + req.file.filename : '/uploads/project-default.jpg'
    };
    db.projects.push(newProject);
    if (writeDatabase(db)) {
        res.json({ success: true, data: newProject });
    } else {
        res.status(500).json({ error: 'Failed to add project' });
    }
});

app.put('/api/projects/:id', isAuthenticated, uploadImage.single('image'), (req, res) => {
    const db = ensureDbShape(readDatabase());
    const index = db.projects.findIndex(p => p.id === req.params.id);
    if (index !== -1) {
        db.projects[index] = {
            ...db.projects[index],
            title: req.body.title,
            description: req.body.description,
            techStack: parseJsonArray(req.body.techStack),
            date: req.body.date
        };
        if (db.projects[index] && Object.prototype.hasOwnProperty.call(db.projects[index], 'link')) {
            delete db.projects[index].link;
        }
        if (db.projects[index] && Object.prototype.hasOwnProperty.call(db.projects[index], 'liveLink')) {
            delete db.projects[index].liveLink;
        }
        if (req.body && (req.body.removeImage === 'true' || req.body.removeImage === true)) {
            db.projects[index].image = '/uploads/project-default.jpg';
        }
        if (req.file) {
            db.projects[index].image = '/uploads/' + req.file.filename;
        }
        if (writeDatabase(db)) {
            res.json({ success: true, data: db.projects[index] });
        } else {
            res.status(500).json({ error: 'Failed to update project' });
        }
    } else {
        res.status(404).json({ error: 'Project not found' });
    }
});

app.delete('/api/projects/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    db.projects = db.projects.filter(p => p.id !== req.params.id);
    if (writeDatabase(db)) {
        res.json({ success: true });
    } else {
        res.status(500).json({ error: 'Failed to delete project' });
    }
});

app.get('/api/experience', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    res.json(db.experience);
});

app.post('/api/experience', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    const newExperience = {
        id: Date.now().toString(),
        ...req.body,
        achievements: parseJsonArray(req.body.achievements)
    };
    db.experience.push(newExperience);
    if (writeDatabase(db)) {
        res.json({ success: true, data: newExperience });
    } else {
        res.status(500).json({ error: 'Failed to add experience' });
    }
});

app.put('/api/experience/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    const index = db.experience.findIndex(e => e.id === req.params.id);
    if (index !== -1) {
        db.experience[index] = {
            ...db.experience[index],
            ...req.body,
            achievements: parseJsonArray(req.body.achievements)
        };
        if (writeDatabase(db)) {
            res.json({ success: true, data: db.experience[index] });
        } else {
            res.status(500).json({ error: 'Failed to update experience' });
        }
    } else {
        res.status(404).json({ error: 'Experience not found' });
    }
});

app.delete('/api/experience/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    db.experience = db.experience.filter(e => e.id !== req.params.id);
    if (writeDatabase(db)) {
        res.json({ success: true });
    } else {
        res.status(500).json({ error: 'Failed to delete experience' });
    }
});

app.get('/api/blogs', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    res.json(db.blogs);
});

app.post('/api/blogs', isAuthenticated, uploadImage.single('image'), (req, res) => {
    const db = ensureDbShape(readDatabase());
    const newBlog = {
        id: Date.now().toString(),
        title: req.body.title,
        content: req.body.content,
        excerpt: req.body.excerpt,
        date: req.body.date,
        tags: parseJsonArray(req.body.tags),
        image: req.file ? '/uploads/' + req.file.filename : '/uploads/blog-default.jpg'
    };
    db.blogs.push(newBlog);
    if (writeDatabase(db)) {
        res.json({ success: true, data: newBlog });
    } else {
        res.status(500).json({ error: 'Failed to add blog' });
    }
});

app.put('/api/blogs/:id', isAuthenticated, uploadImage.single('image'), (req, res) => {
    const db = ensureDbShape(readDatabase());
    const index = db.blogs.findIndex(b => b.id === req.params.id);
    if (index !== -1) {
        db.blogs[index] = {
            ...db.blogs[index],
            title: req.body.title,
            content: req.body.content,
            excerpt: req.body.excerpt,
            date: req.body.date,
            tags: parseJsonArray(req.body.tags)
        };
        if (req.body && (req.body.removeImage === 'true' || req.body.removeImage === true)) {
            db.blogs[index].image = '/uploads/blog-default.jpg';
        }
        if (req.file) {
            db.blogs[index].image = '/uploads/' + req.file.filename;
        }
        if (writeDatabase(db)) {
            res.json({ success: true, data: db.blogs[index] });
        } else {
            res.status(500).json({ error: 'Failed to update blog' });
        }
    } else {
        res.status(404).json({ error: 'Blog not found' });
    }
});

app.delete('/api/blogs/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    db.blogs = db.blogs.filter(b => b.id !== req.params.id);
    if (writeDatabase(db)) {
        res.json({ success: true });
    } else {
        res.status(500).json({ error: 'Failed to delete blog' });
    }
});

app.get('/api/education', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    res.json(db.education);
});

app.post('/api/education', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    if (!isNonEmptyString(req.body.institution) || !isNonEmptyString(req.body.degree) || !isNonEmptyString(req.body.startDate)) {
        return res.status(400).json({ error: 'Institution, degree, and start date are required' });
    }
    const newEducation = {
        id: Date.now().toString(),
        ...req.body
    };
    db.education.push(newEducation);
    if (writeDatabase(db)) {
        res.json({ success: true, data: newEducation });
    } else {
        res.status(500).json({ error: 'Failed to add education' });
    }
});

app.put('/api/education/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    const index = db.education.findIndex(e => e.id === req.params.id);
    if (index !== -1) {
        db.education[index] = { ...db.education[index], ...req.body };
        if (writeDatabase(db)) {
            res.json({ success: true, data: db.education[index] });
        } else {
            res.status(500).json({ error: 'Failed to update education' });
        }
    } else {
        res.status(404).json({ error: 'Education not found' });
    }
});

app.delete('/api/education/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    db.education = db.education.filter(e => e.id !== req.params.id);
    if (writeDatabase(db)) {
        res.json({ success: true });
    } else {
        res.status(500).json({ error: 'Failed to delete education' });
    }
});

app.post('/api/contact', contactLimiter, (req, res) => {
    const { name, email, subject, message } = req.body;
    if (!isNonEmptyString(name) || !isValidEmail(email) || !isNonEmptyString(message)) {
        return res.status(400).json({ error: 'Name, a valid email, and message are required' });
    }

    const db = ensureDbShape(readDatabase());
    const newMessage = {
        id: Date.now().toString(),
        name: name.trim(),
        email: email.trim(),
        subject: isNonEmptyString(subject) ? subject.trim() : '',
        message: message.trim(),
        createdAt: new Date().toISOString(),
        read: false
    };
    db.messages.unshift(newMessage);
    if (writeDatabase(db)) {
        res.json({ success: true });
    } else {
        res.status(500).json({ error: 'Failed to save message' });
    }
});

app.get('/api/messages', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    res.json(db.messages);
});

app.put('/api/messages/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    const index = db.messages.findIndex(m => m.id === req.params.id);
    if (index === -1) {
        return res.status(404).json({ error: 'Message not found' });
    }
    db.messages[index] = { ...db.messages[index], ...req.body };
    if (writeDatabase(db)) {
        res.json({ success: true, data: db.messages[index] });
    } else {
        res.status(500).json({ error: 'Failed to update message' });
    }
});

app.delete('/api/messages/:id', isAuthenticated, (req, res) => {
    const db = ensureDbShape(readDatabase());
    db.messages = db.messages.filter(m => m.id !== req.params.id);
    if (writeDatabase(db)) {
        res.json({ success: true });
    } else {
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

app.use((err, req, res, next) => {
    if (!err) return next();
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large' });
        }
        return res.status(400).json({ error: err.message });
    }
    const status = err.status || 500;
    return res.status(status).json({ error: status === 500 ? 'Server error' : err.message });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Portfolio: http://localhost:${PORT}`);
    console.log(`Admin Login: http://localhost:${PORT}/login.html`);
});
