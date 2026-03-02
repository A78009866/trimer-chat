// server.js

// تشغيل مكتبة dotenv لقراءة متغيرات البيئة من ملف .env محلياً
require('dotenv').config();

const express = require('express');
const path = require('path');
const session = require('express-session');
const FirebaseStore = require('connect-session-firebase')(session);
const admin = require('firebase-admin');
const { getAuth } = require('firebase-admin/auth');
const { getDatabase } = require('firebase-admin/database');
const cors = require('cors');
const crypto = require('crypto');

const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const DEFAULT_PROFILE_PIC_URL = 'https://res.cloudinary.com/duixjs8az/image/upload/v1765009560/post_media/1765009560909-default_profile.png';

// إعدادات Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

// إعدادات Multer مع CloudinaryStorage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: async (req, file) => {
    let folderName = 'general';

    // تحسين منطق تحديد المجلد
    const url = (req && req.originalUrl) ? req.originalUrl : '';
    if (file.fieldname === 'profile_picture') {
      folderName = 'profile_pics';
    } else if (file.fieldname === 'cover_photo') {
      folderName = 'cover_photos';
    } else if (file.fieldname === 'story_media' || url.includes('/api/stories')) {
      // ملفات القصص تُخزن في مجلد stories
      folderName = 'stories';
    } else if (file.fieldname === 'family_image') {
      folderName = 'families';
    } else if (url.includes('/messages/send')) {
      folderName = 'chat_media';
    } else if (url.includes('/api/posts/create')) {
      folderName = 'post_media';
    } else if (url.includes('/register')) {
      folderName = 'profile_pics';
    } else if (url.includes('/api/reels') || url.includes('/create-reel') || url.includes('/api/reels/create')) {
      folderName = 'reels';
    }

    let format = undefined;
    if (file.mimetype && file.mimetype.startsWith('audio/')) {
      format = 'webm';
    }

    return {
      folder: folderName,
      public_id: Date.now() + '-' + path.parse(file.originalname).name,
      resource_type: 'auto',
      format: format
    };
  },
});

const upload = multer({ storage: storage });

// Initialize Firebase Admin
const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_KEY || '{}');

if (admin.apps.length === 0) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL || "https://trimer-4081b-default-rtdb.firebaseio.com",
  });
}

const firebaseAuth = getAuth();
const db = getDatabase();

const app = express();
const port = process.env.PORT || 3000;

// ---------------- Middleware ----------------
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const corsOptions = {
  origin: ['http://localhost:8100', 'https://chat-trimer.vercel.app'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

app.use(session({
  secret: process.env.SESSION_SECRET || 'a-firebase-secret-key-is-better',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  },
  store: new FirebaseStore({
    database: db,
    collection: 'sessions',
    ttl: 86400
  })
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  if (req.path.startsWith('/api/') || req.path.startsWith('/partials/')) {
    return res.status(401).json({ error: 'Unauthorized', message: 'User session not found or expired.' });
  }
  return res.redirect('/login');
}

// ---------------- Admin middleware (جديد) ----------------
// يسمح فقط للمستخدم الذي يطابق ADMIN_UID أو ADMIN_USERNAME بالوصول
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ ok: false, error: 'Unauthorized' });
    return res.redirect('/login');
  }

  const adminUid = process.env.ADMIN_UID || null; // ضع UID الخاص بك في .env للاستخدام الأفضل
  const adminUsername = process.env.ADMIN_USERNAME || 'brahim1582007'; // اسم المستخدم الافتراضي للأدمن

  const email = req.session.email || '';
  const usernameFromEmail = email.split('@')[0]; // username@trimer.io

  const isAdmin = (adminUid && req.session.userId === adminUid) || (usernameFromEmail === adminUsername);

  if (!isAdmin) {
    if (req.path.startsWith('/api/')) return res.status(403).json({ ok: false, error: 'Forbidden' });
    return res.status(403).send('403 Forbidden — ليس لديك صلاحية الوصول لهذه الصفحة.');
  }
  next();
}

// ---------------- Routes: Pages ----------------
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'views', 'splash.html')); });

app.get('/check-status', (req, res) => {
  if (req.session && req.session.userId) {
    res.redirect('/chat_list');
  } else {
    // توجيه إلى صفحة الحسابات المحفوظة عندما لا يكون المستخدم مسجلاً
    res.redirect('/accounts');
  }
});

// مسار صفحة الحسابات (تُعرض عندما لا يكون المستخدم مسجلاً)
app.get('/accounts', (req, res) => {
  return res.sendFile(path.join(__dirname, 'views', 'accounts.html'));
});

// (تمت المحافظة على روابط العرض الأساسية)
app.get('/chat_list', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'chat_list.html')); });
app.get('/users_list', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'users_list.html')); }); // friends (chats) list
app.get('/all_users', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'all_users.html')); }); // all users + requests
app.get('/chat', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'chat.html')); });
app.get('/chat.html', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'chat.html')); });

app.get('/profile/:userId?', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'profile.html'));
});
app.get('/edit_profile', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'edit_profile.html')); });
app.get('/create-post', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'create_post.html')); });
app.get('/login', (req, res) => { res.sendFile(path.join(__dirname, 'views', 'login.html')); });
app.get('/register', (req, res) => { res.sendFile(path.join(__dirname, 'views', 'register.html')); });

// Reels pages
app.get('/reels', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'reels.html')); });
app.get('/create-reel', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'create_reel.html')); });

// Notifications page
app.get('/notifications', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'views', 'notifications.html')); });

// انقل هذا الجزء للأعلى قليلاً في ملف server.js
app.get('/settings', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'settings.html'));
});

// ---------------- Admin Page route (جديد) ----------------
// الصفحة محمية بطبقة requireAuth ثم requireAdmin
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  return res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

// ---------------- Stories: New feature replacing Families ----------------
// Data model (Firebase RTDB):
// stories/{storyId} = { storyId, userId, caption, media: {url,type,filename,mime}, music, createdAt, expiresAt, viewsCount }
// user_stories/{userId}/{storyId} = true
// story_viewers/{storyId}/{userId} = timestamp

const STORY_DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours by default

// Create a story (multipart: story_media)
app.post('/api/stories/create', requireAuth, upload.single('story_media'), async (req, res) => {
  const userId = req.session.userId;
  const { caption = '', music = '' } = req.body;
  if (!req.file) return res.status(400).json({ ok: false, error: 'Media is required' });

  try {
    const newRef = db.ref('stories').push();
    const storyId = newRef.key;
    const createdAt = Date.now();
    const expiresAt = createdAt + STORY_DEFAULT_TTL_MS;

    const mime = req.file.mimetype || '';
    let mediaType = 'file';
    if (mime.startsWith('image/')) mediaType = 'image';
    else if (mime.startsWith('video/')) mediaType = 'video';
    else if (mime.startsWith('audio/')) mediaType = 'audio';

    const media = {
      url: req.file.path,
      type: mediaType,
      filename: req.file.originalname,
      mime: mime
    };

    const storyData = {
      storyId,
      userId,
      caption: String(caption).trim(),
      media,
      music: music ? String(music).trim() : null,
      createdAt,
      expiresAt,
      viewsCount: 0
    };

    await newRef.set(storyData);
    await db.ref(`user_stories/${userId}/${storyId}`).set(true);

    res.json({ ok: true, storyId, story: storyData });
  } catch (err) {
    console.error('Error creating story:', err);
    res.status(500).json({ ok: false, error: 'Failed to create story' });
  }
});

// Get current user's stories (active)
app.get('/api/stories/my', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    const snap = await db.ref('stories').orderByChild('userId').equalTo(userId).once('value');
    const all = snap.val() || {};
    const now = Date.now();
    const stories = Object.values(all).filter(s => (s.expiresAt || now + 1) > now);
    stories.sort((a,b) => (b.createdAt||0) - (a.createdAt||0));
    res.json({ ok: true, stories });
  } catch (e) {
    console.error('Error fetching my stories', e);
    res.status(500).json({ ok: false, error: 'Failed to fetch stories' });
  }
});

// Get stories feed (grouped by user) - returns only still-active stories (unexpired).
app.get('/api/stories/feed', requireAuth, async (req, res) => {
  const now = Date.now();
  try {
    const snap = await db.ref('stories').once('value');
    const obj = snap.val() || {};
    // group by user and only include stories with expiresAt > now
    const byUser = {};
    Object.keys(obj).forEach(sid => {
      const s = obj[sid];
      if (!s || !s.userId) return;
      const expires = Number(s.expiresAt || 0);
      if (expires && expires <= now) return; // expired
      if (!byUser[s.userId]) byUser[s.userId] = { userId: s.userId, stories: [] };
      byUser[s.userId].stories.push(s);
    });
    // attach minimal user info for each group
    const groups = [];
    for (const uid of Object.keys(byUser)) {
      const uSnap = await db.ref(`profiles/${uid}`).once('value');
      const profile = uSnap.val() || {};
      const storiesList = byUser[uid].stories.sort((a,b) => (a.createdAt||0) - (b.createdAt||0)); // older-first for playback sequence
      groups.push({
        userId: uid,
        username: profile.username || 'مستخدم',
        profile_picture_url: profile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
        is_verified: !!profile.is_verified,
        stories: storiesList
      });
    }
    // sort groups: people with newest stories first
    groups.sort((a,b) => {
      const aLast = a.stories && a.stories.length ? (a.stories[a.stories.length-1].createdAt||0) : 0;
      const bLast = b.stories && b.stories.length ? (b.stories[b.stories.length-1].createdAt||0) : 0;
      return bLast - aLast;
    });
    res.json({ ok: true, groups });
  } catch (err) {
    console.error('Error fetching stories feed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch feed' });
  }
});

// Get a single story
app.get('/api/stories/:storyId', requireAuth, async (req, res) => {
  const { storyId } = req.params;
  if (!storyId) return res.status(400).json({ ok: false, error: 'storyId required' });
  try {
    const snap = await db.ref(`stories/${storyId}`).once('value');
    if (!snap.exists()) return res.status(404).json({ ok: false, error: 'Story not found' });
    const story = snap.val();
    // if expired, return 404
    if (story.expiresAt && Number(story.expiresAt) <= Date.now()) return res.status(404).json({ ok: false, error: 'Story expired' });
    res.json({ ok: true, story });
  } catch (err) {
    console.error('Error fetching story:', err);
    res.status(500).json({ ok: false });
  }
});

// Mark a view on a story (current user watches it). increments viewsCount and records viewer.
app.post('/api/stories/:storyId/view', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { storyId } = req.params;
  if (!storyId) return res.status(400).json({ ok: false, error: 'storyId required' });

  try {
    const storyRef = db.ref(`stories/${storyId}`);
    const storySnap = await storyRef.once('value');
    if (!storySnap.exists()) return res.status(404).json({ ok: false });
    const story = storySnap.val();

    // don't double-count: if viewer already exists, only update timestamp
    const viewerRef = db.ref(`story_viewers/${storyId}/${userId}`);
    const existing = await viewerRef.once('value');
    if (!existing.exists()) {
      // increment viewsCount
      await storyRef.child('viewsCount').transaction((c) => (c || 0) + 1);
    }
    await viewerRef.set(admin.database.ServerValue.TIMESTAMP);

    // optional: create notification for owner (but do not spam)
    try {
      if (story.userId && story.userId !== userId) {
        const fromProfileSnap = await db.ref(`profiles/${userId}`).once('value');
        const fromProfile = fromProfileSnap.val() || {};
        const notifRef = db.ref(`notifications/${story.userId}`).push();
        const notifData = {
          id: notifRef.key,
          type: 'story_view',
          from_user_id: userId,
          from_username: fromProfile.username || 'مستخدم',
          from_profile_picture_url: fromProfile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
          storyId,
          timestamp: admin.database.ServerValue.TIMESTAMP,
          is_read: false
        };
        await notifRef.set(notifData);
      }
    } catch (nerr) {
      console.error('Failed to create story_view notification:', nerr);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Error marking story view:', err);
    res.status(500).json({ ok: false });
  }
});

// Delete a story (only creator)
app.delete('/api/stories/:storyId', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { storyId } = req.params;
  if (!storyId) return res.status(400).json({ ok: false, error: 'storyId required' });

  try {
    const storyRef = db.ref(`stories/${storyId}`);
    const snap = await storyRef.once('value');
    if (!snap.exists()) return res.status(404).json({ ok: false, error: 'Story not found' });
    const story = snap.val();
    if (story.userId !== userId) return res.status(403).json({ ok: false, error: 'Forbidden' });

    // remove story and indexes
    await storyRef.remove();
    await db.ref(`user_stories/${userId}/${storyId}`).remove().catch(()=>{});
    await db.ref(`story_viewers/${storyId}`).remove().catch(()=>{});

    res.json({ ok: true, message: 'Story deleted' });
  } catch (err) {
    console.error('Error deleting story:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Periodic cleaner to remove expired stories and their indices (runs every 5 minutes)
setInterval(async () => {
  try {
    const now = Date.now();
    const snap = await db.ref('stories').once('value');
    const all = snap.val() || {};
    const updates = {};
    const toRemoveStoryIds = [];

    Object.keys(all).forEach(storyId => {
      const s = all[storyId];
      if (!s) return;
      const expires = Number(s.expiresAt || 0);
      if (expires && expires <= now) {
        toRemoveStoryIds.push(storyId);
        updates[`stories/${storyId}`] = null;
        updates[`story_viewers/${storyId}`] = null;
        // also remove from user index
        if (s.userId) updates[`user_stories/${s.userId}/${storyId}`] = null;
      }
    });

    if (Object.keys(updates).length > 0) {
      await db.ref().update(updates);
      if (toRemoveStoryIds.length) {
        console.log('Cleaned expired stories:', toRemoveStoryIds.length);
      }
    }
  } catch (e) {
    console.error('Story cleanup error', e);
  }
}, 5 * 60 * 1000); // every 5 minutes

// ---------------- Helper: Friend Utilities ----------------
async function areFriends(userA, userB) {
  if (!userA || !userB) return false;
  const snap = await db.ref(`friends/${userA}/${userB}`).once('value');
  return snap.exists();
}

// ---------------- Helper: Normalize stored comments ----------------
function normalizeStoredComment(val) {
  // val: raw object from DB
  const commentId = val.commentId || val.id || val.key || val.keyId || '';
  const content = val.content || val.commentContent || val.text || '';
  const timestamp = (typeof val.timestamp === 'number') ? val.timestamp : (val.timestamp ? Number(val.timestamp) : Date.now());

  let user = {};
  if (val.user && typeof val.user === 'object') {
    user.userId = val.user.userId || val.user.id || val.user.uid || val.userId || '';
    user.username = val.user.username || val.user.displayName || val.user.name || val.username || 'مستخدم';
    user.profile_picture_url = val.user.profile_picture_url || val.user.photoURL || val.profile_picture_url || DEFAULT_PROFILE_PIC_URL;
  } else {
    user.userId = val.userId || val.userID || val.from_user_id || '';
    user.username = val.username || val.from_username || 'مستخدم';
    user.profile_picture_url = val.profile_picture_url || DEFAULT_PROFILE_PIC_URL;
  }

  user.userId = user.userId || '';
  user.username = user.username || 'مستخدم';
  user.profile_picture_url = user.profile_picture_url || DEFAULT_PROFILE_PIC_URL;

  // include likes/replies counts if present (backwards compatible)
  const likesCount = typeof val.likes === 'number' ? val.likes : (val.likesCount || 0);
  const repliesCount = typeof val.repliesCount === 'number' ? val.repliesCount : (val.replies_count || 0);

  return {
    commentId,
    postId: val.postId || '',
    content,
    timestamp,
    user,
    likes: likesCount || 0,
    repliesCount: repliesCount || 0
  };
}

// helper to count children in a snapshot
function countSnapshotChildren(snap) {
  let c = 0;
  snap.forEach(() => c++);
  return c;
}

// ---------------- API: Admin endpoints (existing) ----------------

// Get all users (only admin)
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const snap = await db.ref('profiles').once('value');
    const profiles = snap.val() || {};
    const users = Object.values(profiles).map(u => ({
      id: u.id,
      username: u.username,
      full_name: u.full_name,
      email: u.email,
      profile_picture_url: u.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
      is_online: !!u.is_online,
      is_verified: !!u.is_verified,
      bio: u.bio || ''
    }));
    res.json({ ok: true, users });
  } catch (error) {
    console.error('Error fetching admin users:', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب المستخدمين.' });
  }
});

// Verify/unverify a user (only admin)
// body: { verify: true/false }  (if omitted defaults to true)
app.post('/api/admin/users/:userId/verify', requireAuth, requireAdmin, async (req, res) => {
  const { userId } = req.params;
  const verify = req.body && typeof req.body.verify !== 'undefined' ? !!req.body.verify : true;

  if (!userId) return res.status(400).json({ ok: false, error: 'userId required' });

  try {
    const profileRef = db.ref(`profiles/${userId}`);
    const snap = await profileRef.once('value');
    if (!snap.exists()) return res.status(404).json({ ok: false, error: 'User not found' });

    await profileRef.update({ is_verified: verify });

    // optional: return updated profile
    const updatedSnap = await profileRef.once('value');
    const updatedProfile = updatedSnap.val();

    res.json({ ok: true, user: { id: updatedProfile.id, username: updatedProfile.username, is_verified: !!updatedProfile.is_verified } });
  } catch (error) {
    console.error('Error updating verification:', error);
    res.status(500).json({ ok: false, error: 'فشل في تحديث حالة التحقق.' });
  }
});

// ---------------- Routes: Pages & Helpers (partials) ----------------
// Update or remove any server-side partials that returned families earlier.
// Provide a minimal partials/families route that redirects or returns story-based HTML to keep compatibility.

app.get('/partials/families', requireAuth, async (req, res) => {
  // This endpoint used to render families; keep backwards compatibility by returning a simple message or redirect.
  // Redirecting to main chat content (client now shows stories tray).
  res.redirect('/chat_list');
});

// If there was chat_content that included families, keep it but remove families content.
// We'll return the existing posts partial (used by HTMX) - reuse the /partials/posts implementation below.

// ---------------- Routes: Posts/Feed/Comments etc. (kept from original) ----------------

// API: Get Single Post by ID (kept)
app.get('/api/posts/one/:postId', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  const { postId } = req.params;

  try {
    const postSnap = await db.ref(`posts/${postId}`).once('value');
    if (!postSnap.exists()) return res.status(404).json({ ok: false, error: 'Post not found' });

    let post = postSnap.val();
    
    // Fetch User Info
    const userSnap = await db.ref(`profiles/${post.userId}`).once('value');
    const userData = userSnap.val() || {};
    
    // Check Like Status
    const likeSnap = await db.ref(`likes/${postId}/${currentUserId}`).once('value');
    const isLiked = likeSnap.exists();

    const finalPost = {
      ...post,
      commentsCount: post.commentsCount || 0,
      is_liked: isLiked,
      user: {
        username: userData.username || 'مستخدم',
        profile_picture_url: userData.profile_picture_url || 'https://via.placeholder.com/150',
        is_online: !!userData.is_online,
        is_verified: !!userData.is_verified
      }
    };

    res.json({ ok: true, post: finalPost });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false });
  }
});
// دعم المسار القصير /post مع تمرير الاستعلامات (مثلاً /post?id=XYZ)
app.get('/post', requireAuth, (req, res) => {
  const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  return res.redirect(`/post.html${qs}`);
});
// API: بحث بسيط يجمع من posts, reels, profiles (فلترة بسيطة على الخادم)
app.get('/api/search', requireAuth, async (req, res) => {
  try {
    const qRaw = String(req.query.q || '').trim();
    const q = qRaw.toLowerCase();
    if (!q) return res.json({ ok: true, posts: [], reels: [], people: [] });

    // جلب البيانات الأساسية
    const [postsSnap, reelsSnap, profilesSnap] = await Promise.all([
      db.ref('posts').once('value'),
      db.ref('reels').once('value'),
      db.ref('profiles').once('value')
    ]);

    const profilesObj = profilesSnap.val() || {};
    // Normalize profiles array
    const profilesArr = Object.values(profilesObj).map(p => ({
      id: p.id || p.uid || '',
      username: (p.username || '').toLowerCase(),
      usernameRaw: p.username || '',
      full_name: (p.full_name || '').toLowerCase(),
      full_nameRaw: p.full_name || '',
      profile_picture_url: p.profile_picture_url || ''
    }));

    // search people
    const people = profilesArr.filter(u => {
      return (u.username && u.username.includes(q)) || (u.full_name && u.full_name.includes(q));
    }).slice(0, 30).map(u => ({ id: u.id, username: u.usernameRaw, full_name: u.full_nameRaw, profile_picture_url: u.profile_picture_url }));

    // search posts (check content + author username/full_name)
    const postsObj = postsSnap.val() || {};
    const postsArr = Object.values(postsObj);
    const matchedPosts = [];
    for (const p of postsArr) {
      const content = (p.content || '').toLowerCase();
      const author = profilesObj[p.userId] || {};
      const authorName = (author.username || '').toLowerCase();
      const authorFull = (author.full_name || '').toLowerCase();
      if (content.includes(q) || authorName.includes(q) || authorFull.includes(q)) {
        matchedPosts.push({
          postId: p.postId || p.id || '',
          userId: p.userId || '',
          content: p.content || '',
          timestamp: p.timestamp || 0,
          media: p.media || null,
          user: {
            username: author.username || author.displayName || 'مستخدم',
            profile_picture_url: author.profile_picture_url || ''
          }
        });
      }
      if (matchedPosts.length >= 30) break;
    }

    // search reels (description + author)
    const reelsObj = reelsSnap.val() || {};
    const reelsArr = Object.values(reelsObj);
    const matchedReels = [];
    for (const r of reelsArr) {
      const desc = (r.description || '').toLowerCase();
      const author = profilesObj[r.userId] || {};
      const authorName = (author.username || '').toLowerCase();
      const authorFull = (author.full_name || '').toLowerCase();
      if (desc.includes(q) || authorName.includes(q) || authorFull.includes(q)) {
        matchedReels.push({
          reelId: r.reelId || r.id || '',
          userId: r.userId || '',
          description: r.description || '',
          timestamp: r.timestamp || 0,
          videoUrl: r.videoUrl || r.video_url || '',
          user: {
            username: author.username || author.displayName || 'مستخدم',
            profile_picture_url: author.profile_picture_url || ''
          }
        });
      }
      if (matchedReels.length >= 30) break;
    }

    res.json({ ok: true, posts: matchedPosts, reels: matchedReels, people: people });
  } catch (err) {
    console.error('Search API error:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});
// --- helper: detect if client wants JSON (AJAX) ---
function clientWantsJson(req) {
  return (req.xhr) || (req.headers.accept && req.headers.accept.indexOf('application/json') !== -1);
}

// ---------------- Routes: Auth Logic ----------------
app.post('/login', async (req, res) => {
  const { username } = req.body;
  const wantsJson = clientWantsJson(req);

  try {
    if (!username) throw new Error('اسم المستخدم مطلوب');
    const email = `${username}@trimer.io`;
    const userRecord = await firebaseAuth.getUserByEmail(email);
    req.session.userId = userRecord.uid;
    req.session.email = userRecord.email;
    await req.session.save();
    
    // Set Online on Login
    await db.ref(`profiles/${userRecord.uid}`).update({
      is_online: true,
      last_seen: admin.database.ServerValue.TIMESTAMP
    });

    if (wantsJson) {
      // return some public info for client to save locally AFTER successful login
      const profileSnap = await db.ref(`profiles/${userRecord.uid}`).once('value');
      const profile = profileSnap.val() || {};
      return res.json({
        ok: true,
        redirect: '/chat_list',
        username: profile.username || username,
        full_name: profile.full_name || username,
        profile_picture_url: profile.profile_picture_url || profile.photoURL || DEFAULT_PROFILE_PIC_URL
      });
    }

    res.redirect('/chat_list');
  } catch (error) {
    const msg = (error && error.message) ? error.message : 'Invalid username or password.';
    if (wantsJson) {
      return res.status(403).json({ ok: false, error: msg });
    }
    res.redirect('/login?error=' + encodeURIComponent('Invalid username or password.'));
  }
});

// استبدال مسار /register بالمعدّل: يرد JSON عند طلب AJAX، ويعطي رسائل خطأ واضحة
app.post('/register', upload.fields([{ name: 'profile_picture' }, { name: 'cover_photo' }]), async (req, res) => {
  const wantsJson = clientWantsJson(req);
  const { username, password, full_name } = req.body;
  let profile_picture_url = DEFAULT_PROFILE_PIC_URL;
  let cover_photo_url = '';

  try {
    // Basic server-side validations
    if (!username || String(username).trim().length === 0) {
      const errMsg = 'اسم المستخدم مطلوب.';
      if (wantsJson) return res.status(400).json({ ok: false, error: errMsg });
      return res.redirect('/register?error=' + encodeURIComponent(errMsg));
    }
    if (/\s/.test(username)) {
      const errMsg = 'لا يجب أن يحتوي اسم المستخدم على مسافات.';
      if (wantsJson) return res.status(400).json({ ok: false, error: errMsg });
      return res.redirect('/register?error=' + encodeURIComponent(errMsg));
    }
    if (!/^[A-Za-z0-9._-]{3,32}$/.test(username)) {
      const errMsg = 'اسم المستخدم يجب أن يتكون من أحرف وأرقام ونقاط أو _ أو - وطوله بين 3 و 32.';
      if (wantsJson) return res.status(400).json({ ok: false, error: errMsg });
      return res.redirect('/register?error=' + encodeURIComponent(errMsg));
    }
    if (!password || password.length < 6) {
      const errMsg = 'كلمة المرور قصيرة؛ يجب أن تكون 6 أحرف على الأقل.';
      if (wantsJson) return res.status(400).json({ ok: false, error: errMsg });
      return res.redirect('/register?error=' + encodeURIComponent(errMsg));
    }

    const email = `${username}@trimer.io`;

    // process uploaded files (if any)
    if (req.files) {
      if (req.files.profile_picture) profile_picture_url = req.files.profile_picture[0].path;
      if (req.files.cover_photo) cover_photo_url = req.files.cover_photo[0].path;
    }

    const userRecord = await firebaseAuth.createUser({
      email: email, password: password, displayName: username, photoURL: profile_picture_url
    });

    const profileData = {
      id: userRecord.uid,
      username: username,
      full_name: full_name || username,
      email: email,
      profile_picture_url: profile_picture_url,
      cover_photo_url: cover_photo_url,
      is_online: true,
      is_verified: false,
      bio: '',
      last_seen: admin.database.ServerValue.TIMESTAMP,
      postsCount: 0
    };

    await db.ref('profiles/' + userRecord.uid).set(profileData);

    req.session.userId = userRecord.uid;
    req.session.email = email;
    await req.session.save();

    if (wantsJson) {
      return res.json({
        ok: true,
        redirect: '/chat_list',
        username: username,
        full_name: profileData.full_name,
        profile_picture_url: profile_picture_url
      });
    }

    res.redirect('/chat_list');
  } catch (error) {
    // clear, user-friendly error messages
    let errMsg = 'فشل في إنشاء الحساب.';
    if (error && error.code) {
      if (error.code === 'auth/email-already-exists' || (error.message && error.message.includes('already exists'))) {
        errMsg = 'اسم المستخدم مأخوذ بالفعل.';
      } else if (error.code === 'auth/invalid-password') {
        errMsg = 'كلمة المرور غير صالحة.';
      } else {
        errMsg = error.message || errMsg;
      }
    } else if (error && error.message) {
      errMsg = error.message;
    }

    console.error('Register error:', error);

    if (wantsJson) {
      return res.status(400).json({ ok: false, error: errMsg });
    }
    res.redirect('/register?error=' + encodeURIComponent(errMsg));
  }
});


app.get('/logout', async (req, res) => {
  // Set Offline on Logout
  if (req.session && req.session.userId) {
    try {
      await db.ref(`profiles/${req.session.userId}`).update({
        is_online: false,
        last_seen: admin.database.ServerValue.TIMESTAMP
      });
    } catch (e) {
      console.error('Error setting offline on logout', e);
    }
  }

  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    // بعد تسجيل الخروج نوجّه المستخدم إلى صفحة الحسابات المحفوظة
    res.redirect('/accounts');
  });
});

// ---------------- Active Status Heartbeat ----------------
// استقبال إشارة النشاط من العميل
app.post('/api/status/heartbeat', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    await db.ref(`profiles/${userId}`).update({
      is_online: true,
      last_seen: admin.database.ServerValue.TIMESTAMP
    });
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false });
  }
});

// ---------------- Helper: Family Utilities (REMOVED) ----------------
// All family-specific helpers and middleware removed (feature replaced by Stories).

// ---------------- Helper: Normalize stored comments (already above) ----------------
// (function normalizeStoredComment defined earlier)

// helper to count children in a snapshot (already defined earlier)

// ---------------- API: Admin endpoints (existing earlier) ----------------// (kept)

// ---------------- API: Chat & Messages (kept) ----------------

app.get('/api/chats', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    const chatRefs = db.ref(`chats/${userId}`);
    const chatSnap = await chatRefs.once('value');
    const chats = [];
    const contactIds = [];

    chatSnap.forEach(childSnap => {
      const chat = childSnap.val();
      chats.push(chat);
      contactIds.push(chat.contact_id);
    });

    const profiles = {};
    const profilePromises = contactIds.map(id => db.ref(`profiles/${id}`).once('value'));
    const profileSnapshots = await Promise.all(profilePromises);

    profileSnapshots.forEach((snap, index) => {
      profiles[contactIds[index]] = snap.val();
    });

    const finalChats = chats.map(chat => ({
      ...chat,
      contact_profile: profiles[chat.contact_id] || { username: 'مستخدم', profile_picture_url: 'https://via.placeholder.com/40', is_online: false }
    }));

    finalChats.sort((a, b) => b.last_message_timestamp - a.last_message_timestamp);
    res.json({ ok: true, chats: finalChats });
  } catch (error) {
    res.status(500).json({ ok: false, error: 'فشل في جلب المحادثات.' });
  }
});

app.get('/api/messages/:contactId', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const contactId = req.params.contactId;
  const { limit = 50 } = req.query;

  if (!contactId) return res.status(400).json({ ok: false, error: 'Contact ID missing' });

  const chatRoomId = [userId, contactId].sort().join('_');
  const messagesRef = db.ref(`messages/${chatRoomId}`);

  try {
    const messagesSnap = await messagesRef
      .orderByChild('timestamp')
      .limitToLast(Number(limit))
      .once('value');

    const messages = [];
    messagesSnap.forEach(childSnap => {
      const val = childSnap.val();
      messages.push({
        ...val, // جلب كل البيانات
        messageId: childSnap.key, // التأكد من أن الـ ID موجود
        reaction: val.reaction || null // [مهم] قراءة التفاعل المحفوظ
      });
    });

    res.json({ ok: true, messages: messages });

  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: 'Error fetching messages.' });
  }
});

// ارسال رسالة (keep)
app.post('/api/messages/send', upload.array('media'), requireAuth, async (req, res) => {
  try {
    const senderId = req.session.userId;
    
    // صفحة chat.html ترسل المعرف باسم other_id
    let contact_id = req.body.other_id || req.body.contact_id || req.body.contactId;
    
    // تنظيف الـ ID
    if (contact_id) contact_id = String(contact_id).replace(/['\"]+/g, '').trim();

    const content = req.body.content || '';
    const reply_to_id = req.body.replied_to_id || null; // لاحظ: الاسم في chat.html هو replied_to_id
    const reply_to_sender = req.body.replied_to_sender || null;
    const reply_to_content = req.body.replied_to_content || null;
    
    // جلب الملفات المرفوعة
    const files = req.files || [];

    if (!contact_id) {
      return res.status(400).json({ ok: false, error: 'Target user ID is missing' });
    }

    // إذا لم يكن هناك نص ولا ملفات، نعتبرها رسالة فارغة
    if (!content.trim() && files.length === 0) {
       return res.status(400).json({ ok: false, error: 'لا يمكن إرسال رسالة فارغة' });
    }

    const chatRoomId = [senderId, contact_id].sort().join('_');
    const timestamp = admin.database.ServerValue.TIMESTAMP;
    const messageRef = db.ref(`messages/${chatRoomId}`).push();
    const messageId = messageRef.key;

    // === التصحيح هنا: إعداد كائن media ليتوافق مع chat.html ===
    let mediaObject = null;
    
    if (files.length > 0) {
      const file = files[0]; // نأخذ الملف الأول لأن chat.html يدعم عرض ملف واحد لكل رسالة
      let type = 'file';
      
      if (file.mimetype.startsWith('image/')) type = 'image';
      else if (file.mimetype.startsWith('video/')) type = 'video';
      else if (file.mimetype.startsWith('audio/') || file.mimetype === 'audio/webm') type = 'audio';
      
      mediaObject = {
        url: file.path, 
        type: type,
        filename: file.originalname
      };
    }
    // =========================================================

    const newMessage = {
      id: messageId,
      messageId: messageId, // تكرار للتأكد
      senderId: senderId,
      content: content,
      media: mediaObject, // حفظنا الكائن بالاسم الذي ينتظره chat.html
      timestamp: timestamp,
      is_read: false,
      // بيانات الرد إذا وجدت
      replied_to_id: reply_to_id,
      replied_to_sender: reply_to_sender,
      replied_to_content: reply_to_content
    };

    // 1. حفظ الرسالة
    await messageRef.set(newMessage);

    // 2. تحديث نص المعاينة (Preview) في قائمة الشات
    let previewText = content;
    if (!content && mediaObject) {
      const type = mediaObject.type;
      previewText = type === 'image' ? '📷 صورة' : type === 'video' ? '🎥 فيديو' : type === 'audio' ? '🎤 رسالة صوتية' : '📎 ملف مرفق';
    }

    // 3. تحديث قائمة المحادثات (Chat List) للطرفين
    const updates = {};
    
    // التحديث عند الطرف الآخر (المستقبل)
    updates[`chats/${contact_id}/${senderId}`] = {
      last_message_content: previewText,
      last_message_timestamp: timestamp,
      contact_id: senderId, // الصديق بالنسبة له هو أنا (المرسل)
      unread_count: admin.database.ServerValue.increment(1),
      last_message_sender_id: senderId,
      last_message_is_read: false
    };

    // التحديث عندي (المرسل)
    updates[`chats/${senderId}/${contact_id}`] = {
      last_message_content: previewText,
      last_message_timestamp: timestamp,
      contact_id: contact_id, // الصديق بالنسبة لي هو هو
      unread_count: 0, // أنا قرأت رسالتي
      last_message_sender_id: senderId,
      last_message_is_read: false
    };

    await db.ref().update(updates);

    // 4. إرسال استجابة بنجاح
    res.json({ ok: true, messageId, messageData: newMessage });

  } catch (error) {
    console.error('❌ Error sending message:', error);
    res.status(500).json({ ok: false, error: 'فشل إرسال الرسالة' });
  }
});

app.post('/api/mark_read', requireAuth, async (req, res) => {
  const userId = req.session.userId; // أنا (القارئ)
  const { other_id } = req.body;     // المرسل (الطرف الآخر)

  if (!other_id) return res.status(400).json({ ok: false });

  const chatRoomId = [userId, other_id].sort().join('_');
  const messagesRef = db.ref(`messages/${chatRoomId}`);

  try {
    // 1. تحديث كل رسائل المرسل لتصبح is_read: true في جدول الرسائل
    const messagesSnap = await messagesRef.orderByChild('senderId').equalTo(other_id).once('value');
    const updates = {};
    let hasUpdates = false;
    
    messagesSnap.forEach(childSnap => {
      if (childSnap.val().is_read === false) {
        updates[`${childSnap.key}/is_read`] = true;
        hasUpdates = true;
      }
    });
    
    if (hasUpdates) {
      await messagesRef.update(updates);
    }

    // 2. تصفير العداد لدي (أنا القارئ)
    await db.ref(`chats/${userId}/${other_id}`).update({ unread_count: 0 });

    // 3. (الجديد) تحديث ملخص الدردشة عند "الطرف الآخر" ليظهر له الصحين الخضر
    // نذهب لملف الطرف الآخر -> المحادثة معي -> ونجعل آخر رسالة مقروءة
    await db.ref(`chats/${other_id}/${userId}`).update({
      last_message_is_read: true
    });

    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false });
  }
});

// ---------------- API: Message Reactions (existing) ----------------
app.post('/api/messages/:otherId/reactions/:messageId', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { otherId, messageId } = req.params;
  const { reaction } = req.body;

  if (!reaction) {
    return res.status(400).json({ ok: false, error: 'reaction required' });
  }

  const chatId = [userId, otherId].sort().join('_');

  try {
    // تصحيح المسار: الوصول المباشر للرسالة
    const messageRef = db.ref(`messages/${chatId}/${messageId}`);
    const messageSnap = await messageRef.once('value');

    if (!messageSnap.exists()) {
      return res.status(404).json({ ok: false, error: 'Message not found' });
    }

    const message = messageSnap.val();

    // [مهم] حفظ التفاعل داخل كائن الرسالة مباشرة باستخدام update
    await messageRef.update({
      reaction: reaction
    });

    res.json({ ok: true });
  } catch (error) {
    console.error('Add message reaction error:', error);
    res.status(500).json({ ok: false });
  }
});

app.delete('/api/messages/:otherId/reactions/:messageId', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { otherId, messageId } = req.params;

  const chatId = [userId, otherId].sort().join('_');

  try {
    const reactionRef = db.ref(`messages/${chatId}/messages/${messageId}/reaction_from/${userId}`);
    const snap = await reactionRef.once('value');
    if (!snap.exists()) {
      return res.status(404).json({ ok: false, error: 'No reaction found' });
    }

    await reactionRef.remove();

    res.json({ ok: true });
  } catch (error) {
    console.error('Remove message reaction error:', error);
    res.status(500).json({ ok: false });
  }
});

// ---------------- API: Users & Profile ----------------
app.get('/api/users', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  try {
    const friendsSnap = await db.ref(`friends/${currentUserId}`).once('value');
    const friendsObj = friendsSnap.val() || {};
    const friendIds = Object.keys(friendsObj);
    if (friendIds.length === 0) return res.json({ ok: true, users: [] });

    const profilePromises = friendIds.map(id => db.ref(`profiles/${id}`).once('value'));
    const profileSnapshots = await Promise.all(profilePromises);
    const profiles = profileSnapshots.map(snap => snap.val() || {});
    const allChatsSnap = await db.ref(`chats/${currentUserId}`).once('value');
    const allChats = allChatsSnap.val() || {};

    const usersList = profiles.map((user) => {
      const contactId = user.id;
      const chatSummary = allChats[contactId] || {};
      let lastMessage = null;
      if (chatSummary.last_message_content) {
        lastMessage = {
          content: chatSummary.last_message_content,
          timestamp: chatSummary.last_message_timestamp,
          senderId: chatSummary.last_message_sender_id
        };
      }
      return {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        profile_picture_url: user.profile_picture_url || 'https://via.placeholder.com/40',
        last_message: lastMessage,
        unread_count: chatSummary.unread_count || 0,
        is_online: !!user.is_online
      };
    });

    res.json({ ok: true, users: usersList });

  } catch (error) {
    console.error('Error in /api/users:', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب قائمة الأصدقاء.' });
  }
});

// API: لجلب معلومات المستخدم (الصورة والاسم) عند تسجيل الدخول
app.get('/api/get-public-info', async (req, res) => {
    try {
        const username = req.query.username;
        if (!username) return res.json({ found: false });

        // تصحيح: البحث في profiles وليس users
        const profilesRef = db.ref('profiles');
        
        const snapshot = await profilesRef.orderByChild('username').equalTo(username).once('value');

        if (snapshot.exists()) {
            // نأخذ أول نتيجة
            const profileData = Object.values(snapshot.val())[0];
            return res.json({
                found: true,
                full_name: profileData.full_name || username,
                // تأكد من وجود رابط للصورة أو استخدام الافتراضية
                profile_picture_url: profileData.profile_picture_url || 'https://res.cloudinary.com/duixjs8az/image/upload/v1766905033/post_media/1766905033352-default_profile.png'
            });
        }
        res.json({ found: false });
    } catch (error) {
        console.error('Error fetching user info:', error);
        res.json({ found: false });
    }
});

// /api/users/all -> all users with is_friend/request flags
app.get('/api/users/all', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  try {
    const profilesSnap = await db.ref('profiles').once('value');
    const profiles = profilesSnap.val() || {};
    const users = Object.values(profiles).filter(u => u.id !== currentUserId).map(user => ({ id: user.id, username: user.username, full_name: user.full_name, profile_picture_url: user.profile_picture_url || DEFAULT_PROFILE_PIC_URL, is_online: !!user.is_online }));
    const full = await Promise.all(users.map(async (u) => {
      const isFriendSnap = await db.ref(`friends/${currentUserId}/${u.id}`).once('value');
      const outgoing = await db.ref(`friend_requests/${u.id}/${currentUserId}`).once('value'); // request I sent to them
      const incoming = await db.ref(`friend_requests/${currentUserId}/${u.id}`).once('value'); // request they sent to me
      return { ...u, is_friend: isFriendSnap.exists(), request_sent: outgoing.exists(), request_received: incoming.exists() };
    }));
    res.json({ ok: true, users: full });
  } catch (error) {
    console.error('Error /api/users/all', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب المستخدمين.' });
  }
});

// ---------------- API: Friends & Requests ----------------

// Send friend request
app.post('/api/friends/request', requireAuth, async (req, res) => {
  const fromId = req.session.userId;
  const { to_id } = req.body;
  if (!to_id) return res.status(400).json({ ok: false, error: 'to_id required' });
  if (fromId === to_id) return res.status(400).json({ ok: false, error: 'Cannot friend yourself' });

  try {
    const already = await areFriends(fromId, to_id);
    if (already) return res.status(409).json({ ok: false, error: 'Already friends' });

    const outgoing = await db.ref(`friend_requests/${to_id}/${fromId}`).once('value');
    if (outgoing.exists()) return res.status(409).json({ ok: false, error: 'Request already sent' });

    await db.ref(`friend_requests/${to_id}/${fromId}`).set({ from: fromId, timestamp: admin.database.ServerValue.TIMESTAMP });

    try {
      const fromProfileSnap = await db.ref(`profiles/${fromId}`).once('value');
      const fromProfile = fromProfileSnap.val() || {};
      const notifRef = db.ref(`notifications/${to_id}`).push();
      const notifData = {
        id: notifRef.key,
        type: 'friend_request',
        from_user_id: fromId,
        from_username: fromProfile.username || 'مستخدم',
        from_profile_picture_url: fromProfile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
        timestamp: admin.database.ServerValue.TIMESTAMP,
        is_read: false
      };
      await notifRef.set(notifData);
    } catch (nerr) {
      console.error('Failed to create friend_request notification:', nerr);
    }

    res.json({ ok: true, message: 'Request sent' });
  } catch (error) {
    console.error('Error sending friend request', error);
    res.status(500).json({ ok: false, error: 'Failed to send request' });
  }
});

// Accept friend request
app.post('/api/friends/accept', requireAuth, async (req, res) => {
  const toId = req.session.userId;
  const { from_id } = req.body;
  if (!from_id) return res.status(400).json({ ok: false, error: 'from_id required' });

  try {
    const requestSnap = await db.ref(`friend_requests/${toId}/${from_id}`).once('value');
    if (!requestSnap.exists()) return res.status(404).json({ ok: false, error: 'Request not found' });

    const ts = admin.database.ServerValue.TIMESTAMP;

    await db.ref(`friends/${toId}/${from_id}`).set({ since: ts });
    await db.ref(`friends/${from_id}/${toId}`).set({ since: ts });

    await db.ref(`friend_requests/${toId}/${from_id}`).remove();
    await db.ref(`friend_requests/${from_id}/${toId}`).remove();

    try {
      const fromProfileSnap = await db.ref(`profiles/${toId}`).once('value');
      const fromProfile = fromProfileSnap.val() || {};
      const notifRef = db.ref(`notifications/${from_id}`).push();
      const notifData = {
        id: notifRef.key,
        type: 'friend_accept',
        from_user_id: toId,
        from_username: fromProfile.username || 'مستخدم',
        from_profile_picture_url: fromProfile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
        timestamp: admin.database.ServerValue.TIMESTAMP,
        is_read: false
      };
      await notifRef.set(notifData);
    } catch (nerr) {
      console.error('Failed to create friend_accept notification:', nerr);
    }

    res.json({ ok: true, message: 'Friend added' });
  } catch (error) {
    console.error('Error accepting friend request', error);
    res.status(500).json({ ok: false });
  }
});

// مسار حذف منشور (Post)
app.delete('/api/posts/:id', async (req, res) => {
  try {
    const postId = req.params.id;
    // هنا يتم الحذف من قاعدة البيانات الخاصة بك (Firebase كمثال)
     await db.ref('posts').child(postId).remove(); 
    
    console.log(`تم حذف المنشور: ${postId}`);
    res.json({ ok: true, message: "تم الحذف بنجاح" });
  } catch (error) {
    console.error("خطأ في الحذف:", error);
    res.status(500).json({ ok: false, error: "فشل حذف المنشور" });
  }
});
// Reject/Decline friend request
app.post('/api/friends/reject', requireAuth, async (req, res) => {
  const toId = req.session.userId;
  const { from_id } = req.body;
  if (!from_id) return res.status(400).json({ ok: false, error: 'from_id required' });

  try {
    await db.ref(`friend_requests/${toId}/${from_id}`).remove();
    res.json({ ok: true });
  } catch (error) {
    console.error('Error rejecting friend request', error);
    res.status(500).json({ ok: false });
  }
});

// Cancel outgoing friend request
app.post('/api/friends/cancel', requireAuth, async (req, res) => {
  const fromId = req.session.userId;
  const { to_id } = req.body;
  if (!to_id) return res.status(400).json({ ok: false, error: 'to_id required' });

  try {
    await db.ref(`friend_requests/${to_id}/${fromId}`).remove();
    res.json({ ok: true });
  } catch (error) {
    console.error('Error cancelling friend request', error);
    res.status(500).json({ ok: false });
  }
});

// Get friend requests incoming
app.get('/api/friends/requests', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    const snap = await db.ref(`friend_requests/${userId}`).once('value');
    const items = [];
    snap.forEach(child => {
      const fromId = child.key;
      const val = child.val();
      items.push({ from: fromId, timestamp: val.timestamp || 0 });
    });

    const profiles = await Promise.all(items.map(i => db.ref(`profiles/${i.from}`).once('value')));
    const out = items.map((it, idx) => {
      const p = profiles[idx].val() || {};
      return { from: it.from, timestamp: it.timestamp, username: p.username || 'مستخدم', profile_picture_url: p.profile_picture_url || DEFAULT_PROFILE_PIC_URL };
    });

    res.json({ ok: true, requests: out });
  } catch (error) {
    console.error('Error getting friend requests:', error);
    res.status(500).json({ ok: false });
  }
});

// Count incoming requests
app.get('/api/friends/requests_count', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    const snap = await db.ref(`friend_requests/${userId}`).once('value');
    let count = 0;
    snap.forEach(() => count++);
    res.json({ ok: true, count });
  } catch (error) {
    console.error('Error counting friend requests', error);
    res.status(500).json({ ok: false });
  }
});

// Get current user's friends with minimal data
app.get('/api/friends', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  try {
    const friendsSnap = await db.ref(`friends/${currentUserId}`).once('value');
    const friendsObj = friendsSnap.val() || {};
    const friendIds = Object.keys(friendsObj);
    if (friendIds.length === 0) return res.json({ ok: true, friends: [] });

    const profilePromises = friendIds.map(id => db.ref(`profiles/${id}`).once('value'));
    const profileSnapshots = await Promise.all(profilePromises);
    const friendsList = profileSnapshots.map(snap => snap.val() || {});
    res.json({ ok: true, friends: friendsList });
  } catch (error) {
    console.error('Error fetching friends', error);
    res.status(500).json({ ok: false });
  }
});

// ---------------- API: Profile ----------------
app.get('/api/profile', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  const requestedUserId = req.query.userId || currentUserId;
  try {
    const profileSnap = await db.ref(`profiles/${requestedUserId}`).once('value');
    const profileData = profileSnap.val();
    if (!profileData) return res.status(404).json({ ok: false });

    let isOwner = requestedUserId === currentUserId;
    let isFriend = false;
    let requestSent = false;
    let requestReceived = false;
    try {
      if (!isOwner) {
        const friendSnap = await db.ref(`friends/${currentUserId}/${requestedUserId}`).once('value');
        isFriend = friendSnap.exists();
        const outgoing = await db.ref(`friend_requests/${requestedUserId}/${currentUserId}`).once('value');
        requestSent = outgoing.exists();
        const incoming = await db.ref(`friend_requests/${currentUserId}/${requestedUserId}`).once('value');
        requestReceived = incoming.exists();
      }
    } catch (e) { /* ignore */ }

    res.json({ ok: true, ...profileData, is_owner: isOwner, is_friend: isFriend, request_sent: requestSent, request_received: requestReceived });
  } catch (error) {
    res.status(500).json({ ok: false });
  }
});

app.get('/api/profile/:userId', requireAuth, async (req, res) => {
  const { userId } = req.params;
  try {
    const profileSnap = await db.ref('profiles').child(userId).once('value');
    const profile = profileSnap.val();
    if (!profile) return res.status(404).json({ ok: false });
    res.json(profile);
  } catch (error) {
    res.status(500).json({ ok: false });
  }
});

// Profile edit (supports multipart)
const uploadProfileFields = upload.fields([
  { name: 'profile_picture', maxCount: 1 },
  { name: 'cover_photo', maxCount: 1 }
]);

app.post('/api/profile/edit', requireAuth, uploadProfileFields, async (req, res) => {
  const userId = req.session.userId;
  const { full_name, username, bio } = req.body;

  if (!username || !full_name) {
    return res.status(400).json({ ok: false, error: 'اسم المستخدم والاسم الكامل مطلوبان.' });
  }

  const updates = {
    full_name: full_name,
    bio: bio,
    username: username,
  };

  try {
    const currentProfileSnap = await db.ref(`profiles/${userId}`).once('value');
    const currentUsername = currentProfileSnap.val().username;

    if (username !== currentUsername) {
      const existingUsernameSnap = await db.ref('profiles')
        .orderByChild('username')
        .equalTo(username)
        .once('value');

      let isUsernameTaken = false;
      existingUsernameSnap.forEach(snap => {
        if (snap.key !== userId) {
          isUsernameTaken = true;
        }
      });

      if (isUsernameTaken) {
        return res.status(409).json({ ok: false, error: 'اسم المستخدم هذا مأخوذ بالفعل.' });
      }

      const newEmail = `${username}@trimer.io`;
      await firebaseAuth.updateUser(userId, {
        displayName: username,
        email: newEmail
      });
      updates.email = newEmail;
    }

    if (req.files && req.files.profile_picture) {
      updates.profile_picture_url = req.files.profile_picture[0].path;
    }
    if (req.files && req.files.cover_photo) {
      updates.cover_photo_url = req.files.cover_photo[0].path;
    }

    await db.ref(`profiles/${userId}`).update(updates);

    res.json({ ok: true, message: 'تم تحديث الملف الشخصي بنجاح.' });

  } catch (error) {
    console.error('Error updating profile:', error);
    if (error.code === 'auth/invalid-email' || error.code === 'auth/email-already-in-use' || error.message && error.message.includes('A user with the provided email already exists')) {
      return res.status(409).json({ ok: false, error: 'اسم المستخدم غير صالح أو مأخوذ.' });
    }
    res.status(500).json({ ok: false, error: 'فشل في تحديث الملف الشخصي.' });
  }
});

// ---------------- API: Posts ----------------

// Create post
app.post('/api/posts/create', requireAuth, upload.single('media'), async (req, res) => {
  const userId = req.session.userId;
  const content = req.body.content ? req.body.content.trim() : '';
  let mediaUrl = null;
  let mediaType = null;

  if (content.length === 0 && !req.file) {
    return res.status(400).json({ ok: false, error: 'المحتوى مطلوب.' });
  }

  if (req.file) {
    mediaUrl = req.file.path;
    const mimeType = req.file.mimetype || '';
    if (mimeType.startsWith('image/')) mediaType = 'image';
    else if (mimeType.startsWith('video/')) mediaType = 'video';
    else if (mimeType.startsWith('audio/')) mediaType = 'audio';
    else mediaType = 'raw';
  }

  try {
    const newPostRef = db.ref('posts').push();
    const postId = newPostRef.key;
    const timestamp = admin.database.ServerValue.TIMESTAMP;

    const postData = {
      postId: postId,
      userId: userId,
      content: content,
      timestamp: timestamp,
      likes: 0,
      commentsCount: 0,
      media: mediaUrl ? { url: mediaUrl, type: mediaType } : null,
    };

    await newPostRef.set(postData);

    const userPostsCountRef = db.ref(`profiles/${userId}/postsCount`);
    await userPostsCountRef.transaction((currentCount) => (currentCount || 0) + 1);

    res.json({ ok: true, message: 'تم النشر', postId: postId });

  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({ ok: false, error: 'فشل في إنشاء المنشور.' });
  }
});

// Get posts (feed)
app.get('/api/posts', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  try {
    const postsSnap = await db.ref('posts')
      .orderByChild('timestamp')
      .limitToLast(50)
      .once('value');

    let posts = [];
    postsSnap.forEach(childSnap => {
      posts.push(childSnap.val());
    });
    posts.reverse();

    const userIds = [...new Set(posts.map(p => p.userId))];
    const profiles = {};
    const defaultProfileUrl = DEFAULT_PROFILE_PIC_URL;

    const profilePromises = userIds.map(userId => db.ref(`profiles/${userId}`).once('value'));
    const profileSnapshots = await Promise.all(profilePromises);

    profileSnapshots.forEach((snap, index) => {
      profiles[userIds[index]] = snap.val();
    });

    const likedStatuses = {};
    const likePromises = posts.map(post => db.ref(`likes/${post.postId}/${currentUserId}`).once('value'));
    const likeSnapshots = await Promise.all(likePromises);

    likeSnapshots.forEach((snap, index) => {
      likedStatuses[posts[index].postId] = snap.val() !== null;
    });

    const finalPosts = posts.map(post => ({
      ...post,
      commentsCount: post.commentsCount || 0,
      is_liked: likedStatuses[post.postId] || false,
      user: {
        username: profiles[post.userId]?.username || 'مستخدم',
        profile_picture_url: profiles[post.userId]?.profile_picture_url || defaultProfileUrl,
        is_online: !!profiles[post.userId]?.is_online,
        is_verified: !!profiles[post.userId]?.is_verified
      }
    }));

    res.json({ ok: true, posts: finalPosts });

  } catch (error) {
    console.error('Error fetching posts:', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب المنشورات.' });
  }
});

// ---------------- Get posts by user (kept) ----------------
app.get('/api/posts/user/:userId', requireAuth, async (req, res) => {
  const requestedUserId = req.params.userId;
  const currentUserId = req.session.userId;

  if (!requestedUserId) return res.status(400).json({ ok: false, error: 'userId required' });

  try {
    const postsSnap = await db.ref('posts')
      .orderByChild('userId')
      .equalTo(requestedUserId)
      .limitToLast(50)
      .once('value');

    const posts = [];
    postsSnap.forEach(child => {
      posts.push(child.val());
    });
    posts.reverse();

    // fetch profile(s) for these posts' authors (mainly one)
    const userIds = [...new Set(posts.map(p => p.userId))];
    const profiles = {};
    if (userIds.length > 0) {
      const profilePromises = userIds.map(id => db.ref(`profiles/${id}`).once('value'));
      const profileSnapshots = await Promise.all(profilePromises);
      profileSnapshots.forEach((snap, idx) => {
        profiles[userIds[idx]] = snap.val() || {};
      });
    }

    // determine liked status by current user for each post
    const likedStatuses = {};
    const likePromises = posts.map(post => db.ref(`likes/${post.postId}/${currentUserId}`).once('value'));
    const likeSnapshots = await Promise.all(likePromises);
    likeSnapshots.forEach((snap, idx) => {
      likedStatuses[posts[idx].postId] = snap.val() !== null;
    });

    const finalPosts = posts.map(post => ({
      ...post,
      commentsCount: post.commentsCount || 0,
      is_liked: likedStatuses[post.postId] || false,
      user: {
        username: profiles[post.userId]?.username || 'مستخدم',
        profile_picture_url: profiles[post.userId]?.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
        is_online: !!profiles[post.userId]?.is_online,
        is_verified: !!profiles[post.userId]?.is_verified
      }
    }));

    res.json({ ok: true, posts: finalPosts });
  } catch (error) {
    console.error('Error fetching user posts:', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب منشورات المستخدم.' });
  }
});

// Like/unlike post (kept)
app.post('/api/posts/:postId/like', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const postId = req.params.postId;

  if (!postId) return res.status(400).json({ ok: false });

  const postRef = db.ref(`posts/${postId}`);
  const userLikeRef = db.ref(`likes/${postId}/${userId}`);

  try {
    const postSnapshot = await postRef.once('value');
    if (!postSnapshot.exists()) return res.status(404).json({ ok: false });

    const likeSnapshot = await userLikeRef.once('value');
    const isLiked = likeSnapshot.val();
    let likesUpdate = 0;
    let action = '';

    if (isLiked) {
      await userLikeRef.remove();
      likesUpdate = -1;
      action = 'unliked';
    } else {
      await userLikeRef.set(admin.database.ServerValue.TIMESTAMP);
      likesUpdate = 1;
      action = 'liked';
    }

    let newLikesCount = 0;
    await postRef.child('likes').transaction((currentCount) => {
      newLikesCount = (currentCount || 0) + likesUpdate;
      return newLikesCount < 0 ? 0 : newLikesCount;
    });

    // إنشاء إشعار للمستخدم صاحب المنشور عندما يقوم شخص آخر بالإعجاب
    try {
      const postData = postSnapshot.val();
      if (action === 'liked' && postData.userId && postData.userId !== userId) {
        const fromProfileSnap = await db.ref(`profiles/${userId}`).once('value');
        const fromProfile = fromProfileSnap.val() || {};
        const notifRef = db.ref(`notifications/${postData.userId}`).push();
        const notifData = {
          id: notifRef.key,
          type: 'post_like',
          from_user_id: userId,
          from_username: fromProfile.username || 'مستخدم',
          from_profile_picture_url: fromProfile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
          postId: postId,
          reelId: null,
          timestamp: admin.database.ServerValue.TIMESTAMP,
          is_read: false
        };
        await notifRef.set(notifData);
      }
    } catch (nerr) {
      console.error('Failed to create post_like notification:', nerr);
    }

    res.json({ ok: true, action: action, newLikes: newLikesCount });

  } catch (error) {
    res.status(500).json({ ok: false });
  }
});

// Comment on post (UPDATED: normalize, return newComments)
app.post('/api/posts/:postId/comment', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const postId = req.params.postId;
  const { content } = req.body;

  if (!postId || !content) return res.status(400).json({ ok: false, error: 'Missing postId or content' });

  try {
    const postRef = db.ref(`posts/${postId}`);
    const postSnapshot = await postRef.once('value');
    if (!postSnapshot.exists()) return res.status(404).json({ ok: false, error: 'Post not found' });

    const userSnapshot = await db.ref(`profiles/${userId}`).once('value');
    const userData = userSnapshot.val() || {};

    const newCommentRef = db.ref(`comments/${postId}`).push();
    const commentId = newCommentRef.key;
    const timestamp = admin.database.ServerValue.TIMESTAMP;

    // Store a consistent normalized comment shape in DB
    const commentData = {
      commentId: commentId,
      postId: postId,
      userId: userId,
      content: content.trim(),
      timestamp: timestamp,
      user: {
        userId: userId,
        username: userData.username || 'مستخدم',
        profile_picture_url: userData.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
      },
      likes: 0,
      repliesCount: 0
    };

    await newCommentRef.set(commentData);

    // increment commentsCount on post (transaction to be safe)
    let newCommentsCount = 0;
    await postRef.child('commentsCount').transaction((currentCount) => {
      newCommentsCount = (currentCount || 0) + 1;
      return newCommentsCount;
    });

    // create notification for post owner (if commenter !== owner)
    try {
      const postData = postSnapshot.val();
      if (postData && postData.userId && postData.userId !== userId) {
        const fromProfileSnap = await db.ref(`profiles/${userId}`).once('value');
        const fromProfile = fromProfileSnap.val() || {};
        const notifRef = db.ref(`notifications/${postData.userId}`).push();
        const notifData = {
          id: notifRef.key,
          type: 'post_comment',
          from_user_id: userId,
          from_username: fromProfile.username || 'مستخدم',
          from_profile_picture_url: fromProfile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
          postId: postId,
          reelId: null,
          commentId: commentId,
          commentContent: commentData.content,
          timestamp: admin.database.ServerValue.TIMESTAMP,
          is_read: false
        };
        await notifRef.set(notifData);
      }
    } catch (nerr) {
      console.error('Failed to create post_comment notification:', nerr);
    }

    // Read back the stored comment (so timestamp is resolved) and return normalized
    const savedSnap = await db.ref(`comments/${postId}`).child(commentId).once('value');
    const savedVal = savedSnap.val() || commentData;
    const normalized = normalizeStoredComment(savedVal);

    res.json({ ok: true, comment: normalized, newComments: newCommentsCount });

  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({ ok: false, error: 'فشل في إضافة التعليق.' });
  }
});

// ---------------- New Feature: Like a comment (kept) ----------------
app.post('/api/posts/:postId/comments/:commentId/like', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { postId, commentId } = req.params;
  if (!postId || !commentId) return res.status(400).json({ ok: false, error: 'postId/commentId required' });

  const likeRef = db.ref(`comment_likes/${postId}/${commentId}/${userId}`);
  const commentRef = db.ref(`comments/${postId}/${commentId}`);

  try {
    const commentSnap = await commentRef.once('value');
    if (!commentSnap.exists()) return res.status(404).json({ ok: false, error: 'Comment not found' });

    const likeSnap = await likeRef.once('value');
    let isLiked = likeSnap.exists();
    let delta = 0;

    if (isLiked) {
      await likeRef.remove();
      delta = -1;
      isLiked = false;
    } else {
      await likeRef.set(admin.database.ServerValue.TIMESTAMP);
      delta = 1;
      isLiked = true;
    }

    // Update likes count on comment atomically
    let newLikesCount = 0;
    await commentRef.child('likes').transaction((current) => {
      newLikesCount = (current || 0) + delta;
      return newLikesCount < 0 ? 0 : newLikesCount;
    });

    // notify comment owner when liked by another user
    try {
      const commentVal = commentSnap.val();
      const commentOwnerId = (commentVal.user && commentVal.user.userId) ? commentVal.user.userId : (commentVal.userId || '');
      if (delta === 1 && commentOwnerId && commentOwnerId !== userId) {
        const fromProfileSnap = await db.ref(`profiles/${userId}`).once('value');
        const fromProfile = fromProfileSnap.val() || {};
        const notifRef = db.ref(`notifications/${commentOwnerId}`).push();
        const notifData = {
          id: notifRef.key,
          type: 'comment_like',
          from_user_id: userId,
          from_username: fromProfile.username || 'مستخدم',
          from_profile_picture_url: fromProfile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
          postId: postId,
          commentId: commentId,
          timestamp: admin.database.ServerValue.TIMESTAMP,
          is_read: false
        };
        await notifRef.set(notifData);
      }
    } catch (nerr) {
      console.error('Failed to create comment_like notification:', nerr);
    }

    res.json({ ok: true, is_liked: isLiked, likes: newLikesCount });

  } catch (error) {
    console.error('Error toggling comment like:', error);
    res.status(500).json({ ok: false, error: 'Failed to toggle comment like' });
  }
});

// ---------------- New Feature: Reply to comment (kept) ----------------
app.post('/api/posts/:postId/comments/:commentId/reply', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { postId, commentId } = req.params;
  const { content } = req.body;
  if (!postId || !commentId || !content) return res.status(400).json({ ok: false, error: 'Missing parameters' });

  try {
    const commentRef = db.ref(`comments/${postId}/${commentId}`);
    const commentSnap = await commentRef.once('value');
    if (!commentSnap.exists()) return res.status(404).json({ ok: false, error: 'Comment not found' });

    const userSnap = await db.ref(`profiles/${userId}`).once('value');
    const userData = userSnap.val() || {};

    const replyRef = db.ref(`comment_replies/${postId}/${commentId}`).push();
    const replyId = replyRef.key;
    const timestamp = admin.database.ServerValue.TIMESTAMP;

    const replyData = {
      id: replyId,
      postId,
      commentId,
      userId,
      username: userData.username || 'مستخدم',
      profile_picture_url: userData.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
      content: content.trim(),
      timestamp: timestamp
    };

    await replyRef.set(replyData);

    // increment repliesCount on comment
    let newRepliesCount = 0;
    await commentRef.child('repliesCount').transaction((current) => {
      newRepliesCount = (current || 0) + 1;
      return newRepliesCount;
    });

    // notify original commenter (if not replying to self)
    try {
      const commentVal = commentSnap.val();
      const commentOwnerId = (commentVal.user && commentVal.user.userId) ? commentVal.user.userId : (commentVal.userId || '');
      if (commentOwnerId && commentOwnerId !== userId) {
        const notifRef = db.ref(`notifications/${commentOwnerId}`).push();
        const notifData = {
          id: notifRef.key,
          type: 'comment_reply',
          from_user_id: userId,
          from_username: userData.username || 'مستخدم',
          from_profile_picture_url: userData.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
          postId,
          commentId,
          replyId,
          replyContent: replyData.content,
          timestamp: admin.database.ServerValue.TIMESTAMP,
          is_read: false
        };
        await notifRef.set(notifData);
      }
    } catch (nerr) {
      console.error('Failed to create comment_reply notification:', nerr);
    }

    res.json({ ok: true, reply: replyData, repliesCount: newRepliesCount });

  } catch (error) {
    console.error('Error creating reply:', error);
    res.status(500).json({ ok: false, error: 'Failed to create reply' });
  }
});

// ---------------- Get comments (UPDATED with enrichments) ----------------
app.get('/api/posts/:postId/comments', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  const { postId } = req.params;
  try {
    const commentsSnap = await db.ref(`comments/${postId}`)
      .orderByChild('timestamp')
      .once('value');

    const comments = [];
    commentsSnap.forEach(childSnap => {
      const v = childSnap.val();
      if (v) comments.push(v);
    });

    // For each comment, fetch likes count, whether current user liked, and latest replies (optionally)
    const enriched = await Promise.all(comments.map(async (c) => {
      const normalized = normalizeStoredComment(c);
      // likes count from comment.likes or count children at comment_likes
      let likesCount = 0;
      try {
        if (typeof c.likes === 'number') {
          likesCount = c.likes;
        } else {
          const likesSnap = await db.ref(`comment_likes/${postId}/${normalized.commentId}`).once('value');
          likesCount = countSnapshotChildren(likesSnap);
        }
      } catch (e) {
        likesCount = normalized.likes || 0;
      }

      // did current user like?
      let isLiked = false;
      try {
        const userLikeSnap = await db.ref(`comment_likes/${postId}/${normalized.commentId}/${currentUserId}`).once('value');
        isLiked = userLikeSnap.exists();
      } catch (e) {}

      // replies count (from comment or by counting)
      let repliesCount = 0;
      try {
        if (typeof c.repliesCount === 'number') repliesCount = c.repliesCount;
        else {
          const repliesSnap = await db.ref(`comment_replies/${postId}/${normalized.commentId}`).once('value');
          repliesCount = countSnapshotChildren(repliesSnap);
        }
      } catch (e) {
        repliesCount = normalized.repliesCount || 0;
      }

      // optionally fetch last few replies (e.g., last 5)
      let recentReplies = [];
      try {
        const repliesSnap = await db.ref(`comment_replies/${postId}/${normalized.commentId}`)
          .orderByChild('timestamp')
          .limitToLast(5)
          .once('value');
        repliesSnap.forEach(r => recentReplies.push(r.val()));
      } catch (e) { recentReplies = []; }

      return {
        ...normalized,
        likes: likesCount,
        is_liked: isLiked,
        repliesCount: repliesCount,
        recentReplies: recentReplies
      };
    }));

    res.json({ ok: true, comments: enriched });
  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب التعليقات.' });
  }
});

// ---------------- Get replies for a specific comment ----------------
app.get('/api/posts/:postId/comments/:commentId/replies', requireAuth, async (req, res) => {
  const { postId, commentId } = req.params;
  try {
    const snap = await db.ref(`comment_replies/${postId}/${commentId}`)
      .orderByChild('timestamp')
      .once('value');
    const replies = [];
    snap.forEach(child => {
      replies.push(child.val());
    });
    res.json({ ok: true, replies: replies });
  } catch (error) {
    console.error('Error fetching replies:', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب الردود.' });
  }
});

// ---------------- Get comments stream (SSE) for main posts ----------------
// SSE helper for sending events
function sseSend(res, event, data) {
  try {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  } catch (e) {
    // ignore
  }
}

app.get('/api/posts/:postId/comments/stream', requireAuth, async (req, res) => {
  const { postId } = req.params;
  if (!postId) return res.status(400).end();

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'Access-Control-Allow-Origin': corsOptions.origin.includes(req.headers.origin) ? req.headers.origin : 'null',
  });
  res.write('\n');

  const commentsRef = db.ref(`comments/${postId}`);

  try {
    // initial snapshot
    const snap = await commentsRef.orderByChild('timestamp').once('value');
    const items = [];
    let lastTs = 0;
    snap.forEach(child => {
      const v = child.val();
      const normalized = normalizeStoredComment(v);
      items.push(normalized);
      if (normalized.timestamp && Number(normalized.timestamp) > lastTs) lastTs = Number(normalized.timestamp);
    });

    sseSend(res, 'comments_snapshot', items);

    const addedQuery = (lastTs > 0) ? commentsRef.orderByChild('timestamp').startAt(lastTs + 1) : commentsRef.orderByChild('timestamp');

    const onChildAdded = (child) => {
      const v = child.val();
      const normalized = normalizeStoredComment(v);
      if (normalized.timestamp && normalized.timestamp <= lastTs) return;
      sseSend(res, 'comment_added', normalized);
      if (normalized.timestamp && Number(normalized.timestamp) > lastTs) lastTs = Number(normalized.timestamp);
    };

    const onChildChanged = (child) => {
      const v = child.val();
      const normalized = normalizeStoredComment(v);
      sseSend(res, 'comment_changed', normalized);
    };

    const onChildRemoved = (child) => {
      const key = child.key || (child.val() && (child.val().commentId || child.val().id));
      sseSend(res, 'comment_removed', { commentId: key });
    };

    addedQuery.on('child_added', onChildAdded);
    commentsRef.on('child_changed', onChildChanged);
    commentsRef.on('child_removed', onChildRemoved);

    req.on('close', () => {
      try {
        addedQuery.off('child_added', onChildAdded);
        commentsRef.off('child_changed', onChildChanged);
        commentsRef.off('child_removed', onChildRemoved);
      } catch (e) { /* ignore */ }
      res.end();
    });

  } catch (err) {
    console.error('SSE comments stream error:', err);
    res.write(`event: error\ndata: ${JSON.stringify({ error: String(err) })}\n\n`);
    res.end();
  }
});

// ---------------- API: Reels Implementation ----------------

// إنشاء ريل جديد
app.post('/api/reels/create', requireAuth, upload.single('media'), async (req, res) => {
  const userId = req.session.userId;
  const description = req.body.description ? req.body.description.trim() : '';
  
  if (!req.file) {
    return res.status(400).json({ ok: false, error: 'الفيديو مطلوب.' });
  }

  try {
    const newReelRef = db.ref('reels').push();
    const reelId = newReelRef.key;
    const timestamp = admin.database.ServerValue.TIMESTAMP;

    const reelData = {
      reelId: reelId,
      userId: userId,
      description: description,
      timestamp: timestamp,
      likes: 0,
      commentsCount: 0,
      videoUrl: req.file.path,
      mimeType: req.file.mimetype
    };

    await newReelRef.set(reelData);
    res.json({ ok: true, reelId: reelId });

  } catch (error) {
    console.error('Error creating reel:', error);
    res.status(500).json({ ok: false, error: 'فشل في رفع الريل.' });
  }
});

app.get('/api/reels/feed', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  try {
    const reelsSnap = await db.ref('reels').once('value');
    let reels = [];
    
    reelsSnap.forEach(snap => {
      const data = snap.val();
      if (data) reels.push(data);
    });

    reels.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

    const finalReels = await Promise.all(reels.map(async (reel) => {
      const userSnap = await db.ref(`profiles/${reel.userId}`).once('value');
      const userData = userSnap.val() || {};
      const likeSnap = await db.ref(`reels_likes/${reel.reelId}/${currentUserId}`).once('value');
      
      return {
        ...reel,
        commentsCount: reel.commentsCount || 0,
        is_liked: likeSnap.exists(),
        user: {
          username: userData.username || 'مستخدم',
          profile_picture_url: userData.profile_picture_url || 'https://via.placeholder.com/150',
          is_online: !!userData.is_online,
          is_verified: !!userData.is_verified
        }
      };
    }));

    res.json({ ok: true, reels: finalReels, currentUserId: currentUserId });
  } catch (error) {
    console.error("خطأ في جلب الريلز:", error);
    res.status(500).json({ ok: false, error: 'Error fetching reels' });
  }
});

app.delete('/api/reels/:reelId', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { reelId } = req.params;

  try {
    const reelRef = db.ref(`reels/${reelId}`);
    const snapshot = await reelRef.once('value');
    const reel = snapshot.val();

    if (!reel) return res.status(404).json({ ok: false, error: 'الريل غير موجود' });
    
    if (reel.userId !== userId) {
      return res.status(403).json({ ok: false, error: 'غير مصرح لك بحذف هذا الريل' });
    }

    await reelRef.remove();
    await db.ref(`reels_likes/${reelId}`).remove();
    await db.ref(`reels_comments/${reelId}`).remove();

    // cleanup comment likes/replies if exist
    await db.ref(`reels_comment_likes/${reelId}`).remove().catch(()=>{});
    await db.ref(`reels_comment_replies/${reelId}`).remove().catch(()=>{});

    res.json({ ok: true, message: 'تم الحذف بنجاح' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: 'فشل الحذف' });
  }
});

app.post('/api/reels/:reelId/like', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { reelId } = req.params;

  const reelRef = db.ref(`reels/${reelId}`);
  const likeRef = db.ref(`reels_likes/${reelId}/${userId}`);

  try {
    const likeSnap = await likeRef.once('value');
    let isLiked = likeSnap.exists();
    let increment = 0;

    if (isLiked) {
      await likeRef.remove();
      increment = -1;
      isLiked = false;
    } else {
      await likeRef.set(admin.database.ServerValue.TIMESTAMP);
      increment = 1;
      isLiked = true;
    }

    await reelRef.child('likes').transaction(count => (count || 0) + increment);
    
    const updatedReelSnap = await reelRef.once('value');
    const updatedReel = updatedReelSnap.val();

    try {
      if (isLiked && updatedReel.userId && updatedReel.userId !== userId) {
        const fromProfileSnap = await db.ref(`profiles/${userId}`).once('value');
        const fromProfile = fromProfileSnap.val() || {};
        const notifRef = db.ref(`notifications/${updatedReel.userId}`).push();
        const notifData = {
          id: notifRef.key,
          type: 'reel_like',
          from_user_id: userId,
          from_username: fromProfile.username || 'مستخدم',
          from_profile_picture_url: fromProfile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
          postId: null,
          reelId: reelId,
          timestamp: admin.database.ServerValue.TIMESTAMP,
          is_read: false
        };
        await notifRef.set(notifData);
      }
    } catch (nerr) {
      console.error('Failed to create reel_like notification:', nerr);
    }

    res.json({ ok: true, likes: updatedReel.likes, is_liked: isLiked });

  } catch (error) {
    res.status(500).json({ ok: false });
  }
});

app.post('/api/reels/:reelId/comment', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { reelId } = req.params;
  const { content } = req.body;

  if (!content) return res.status(400).json({ ok: false });

  try {
    const userSnap = await db.ref(`profiles/${userId}`).once('value');
    const user = userSnap.val();

    const commentRef = db.ref(`reels_comments/${reelId}`).push();
    const commentData = {
      id: commentRef.key,
      userId,
      username: user.username,
      profile_picture_url: user.profile_picture_url,
      content,
      timestamp: admin.database.ServerValue.TIMESTAMP,
      likes: 0,
      repliesCount: 0
    };

    await commentRef.set(commentData);
    await db.ref(`reels/${reelId}/commentsCount`).transaction(c => (c || 0) + 1);

    try {
      const reelSnap = await db.ref(`reels/${reelId}`).once('value');
      const reel = reelSnap.val();
      if (reel && reel.userId && reel.userId !== userId) {
        const fromProfileSnap = await db.ref(`profiles/${userId}`).once('value');
        const fromProfile = fromProfileSnap.val() || {};
        const notifRef = db.ref(`notifications/${reel.userId}`).push();
        const notifData = {
          id: notifRef.key,
          type: 'reel_comment',
          from_user_id: userId,
          from_username: fromProfile.username || 'مستخدم',
          from_profile_picture_url: fromProfile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
          postId: null,
          reelId: reelId,
          commentId: commentData.id,
          commentContent: commentData.content,
          timestamp: admin.database.ServerValue.TIMESTAMP,
          is_read: false
        };
        await notifRef.set(notifData);
      }
    } catch (nerr) {
      console.error('Failed to create reel_comment notification:', nerr);
    }

    res.json({ ok: true, comment: commentData });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false });
  }
});

// New endpoints: like a reel comment (kept)
app.post('/api/reels/:reelId/comments/:commentId/like', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { reelId, commentId } = req.params;
  if (!reelId || !commentId) return res.status(400).json({ ok: false, error: 'reelId/commentId required' });

  const likeRef = db.ref(`reels_comment_likes/${reelId}/${commentId}/${userId}`);
  const commentRef = db.ref(`reels_comments/${reelId}/${commentId}`);

  try {
    const commentSnap = await commentRef.once('value');
    if (!commentSnap.exists()) return res.status(404).json({ ok: false, error: 'Comment not found' });

    const likeSnap = await likeRef.once('value');
    let isLiked = likeSnap.exists();
    let delta = 0;

    if (isLiked) {
      await likeRef.remove();
      delta = -1;
      isLiked = false;
    } else {
      await likeRef.set(admin.database.ServerValue.TIMESTAMP);
      delta = 1;
      isLiked = true;
    }

    // Update likes count on comment atomically
    let newLikesCount = 0;
    await commentRef.child('likes').transaction((current) => {
      newLikesCount = (current || 0) + delta;
      return newLikesCount < 0 ? 0 : newLikesCount;
    });

    // notify comment owner when liked by another user
    try {
      const commentVal = commentSnap.val();
      const commentOwnerId = commentVal.userId || '';
      if (delta === 1 && commentOwnerId && commentOwnerId !== userId) {
        const fromProfileSnap = await db.ref(`profiles/${userId}`).once('value');
        const fromProfile = fromProfileSnap.val() || {};
        const notifRef = db.ref(`notifications/${commentOwnerId}`).push();
        const notifData = {
          id: notifRef.key,
          type: 'comment_like',
          from_user_id: userId,
          from_username: fromProfile.username || 'مستخدم',
          from_profile_picture_url: fromProfile.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
          postId: null,
          reelId: reelId,
          commentId: commentId,
          timestamp: admin.database.ServerValue.TIMESTAMP,
          is_read: false
        };
        await notifRef.set(notifData);
      }
    } catch (nerr) {
      console.error('Failed to create reels comment_like notification:', nerr);
    }

    res.json({ ok: true, is_liked: isLiked, likes: newLikesCount });
  } catch (error) {
    console.error('Error toggling reel comment like:', error);
    res.status(500).json({ ok: false, error: 'Failed to toggle comment like' });
  }
});

// New endpoint: reply to a reel comment (kept)
app.post('/api/reels/:reelId/comments/:commentId/reply', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { reelId, commentId } = req.params;
  const { content } = req.body;
  if (!reelId || !commentId || !content) return res.status(400).json({ ok: false, error: 'Missing parameters' });

  try {
    const commentRef = db.ref(`reels_comments/${reelId}/${commentId}`);
    const commentSnap = await commentRef.once('value');
    if (!commentSnap.exists()) return res.status(404).json({ ok: false, error: 'Comment not found' });

    const userSnap = await db.ref(`profiles/${userId}`).once('value');
    const userData = userSnap.val() || {};

    const replyRef = db.ref(`reels_comment_replies/${reelId}/${commentId}`).push();
    const replyId = replyRef.key;
    const timestamp = admin.database.ServerValue.TIMESTAMP;

    const replyData = {
      id: replyId,
      reelId,
      commentId,
      userId,
      username: userData.username || 'مستخدم',
      profile_picture_url: userData.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
      content: content.trim(),
      timestamp: timestamp
    };

    await replyRef.set(replyData);

    // increment repliesCount on comment
    let newRepliesCount = 0;
    await commentRef.child('repliesCount').transaction((current) => {
      newRepliesCount = (current || 0) + 1;
      return newRepliesCount;
    });

    // notify original commenter (if not replying to self)
    try {
      const commentVal = commentSnap.val();
      const commentOwnerId = commentVal.userId || '';
      if (commentOwnerId && commentOwnerId !== userId) {
        const notifRef = db.ref(`notifications/${commentOwnerId}`).push();
        const notifData = {
          id: notifRef.key,
          type: 'comment_reply',
          from_user_id: userId,
          from_username: userData.username || 'مستخدم',
          from_profile_picture_url: userData.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
          postId: null,
          reelId,
          commentId,
          replyId,
          replyContent: replyData.content,
          timestamp: admin.database.ServerValue.TIMESTAMP,
          is_read: false
        };
        await notifRef.set(notifData);
      }
    } catch (nerr) {
      console.error('Failed to create reels comment_reply notification:', nerr);
    }

    res.json({ ok: true, reply: replyData, repliesCount: newRepliesCount });
  } catch (error) {
    console.error('Error creating reply for reel comment:', error);
    res.status(500).json({ ok: false, error: 'Failed to create reply' });
  }
});

// New endpoint: get replies for a reel comment (kept)
app.get('/api/reels/:reelId/comments/:commentId/replies', requireAuth, async (req, res) => {
  const { reelId, commentId } = req.params;
  try {
    const snap = await db.ref(`reels_comment_replies/${reelId}/${commentId}`)
      .orderByChild('timestamp')
      .once('value');
    const replies = [];
    snap.forEach(child => {
      replies.push(child.val());
    });
    res.json({ ok: true, replies: replies });
  } catch (error) {
    console.error('Error fetching replies for reel comment:', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب الردود.' });
  }
});

app.get('/api/reels/:reelId/comments', requireAuth, async (req, res) => {
  const { reelId } = req.params;
  try {
    const snap = await db.ref(`reels_comments/${reelId}`)
      .orderByChild('timestamp')
      .limitToLast(100)
      .once('value');

    const comments = [];
    snap.forEach(s => {
      const val = s.val();
      if (val) comments.push(val);
    });

    // For each comment, include likes/repliesCount and whether current user liked it
    const currentUserId = req.session.userId;
    const enriched = await Promise.all(comments.map(async (c) => {
      // likes
      let likes = typeof c.likes === 'number' ? c.likes : 0;
      try {
        if (typeof c.likes !== 'number') {
          const likesSnap = await db.ref(`reels_comment_likes/${reelId}/${c.id}`).once('value');
          likes = countSnapshotChildren(likesSnap);
        }
      } catch (e) {}
      let is_liked = false;
      try {
        const userLikeSnap = await db.ref(`reels_comment_likes/${reelId}/${c.id}/${currentUserId}`).once('value');
        is_liked = userLikeSnap.exists();
      } catch (e) {}
      // repliesCount
      let repliesCount = typeof c.repliesCount === 'number' ? c.repliesCount : 0;
      try {
        if (typeof c.repliesCount !== 'number') {
          const repliesSnap = await db.ref(`reels_comment_replies/${reelId}/${c.id}`).once('value');
          repliesCount = countSnapshotChildren(repliesSnap);
        }
      } catch (e) {}
      // recentReplies - last 3
      let recentReplies = [];
      try {
        const rr = await db.ref(`reels_comment_replies/${reelId}/${c.id}`).orderByChild('timestamp').limitToLast(3).once('value');
        rr.forEach(r => recentReplies.push(r.val()));
      } catch (e) {}

      return {
        ...c,
        likes: likes,
        is_liked: is_liked,
        repliesCount: repliesCount,
        recentReplies: recentReplies
      };
    }));

    // sort by timestamp ascending for UI (older first)
    enriched.sort((a,b) => (a.timestamp||0) - (b.timestamp||0));

    res.json({ ok: true, comments: enriched });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false });
  }
});

// ---------------- API: Notifications (kept) ----------------

app.get('/api/notifications', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    const snap = await db.ref(`notifications/${userId}`).once('value');
    const items = [];
    snap.forEach(child => {
      const v = child.val();
      items.push({ id: child.key, ...v });
    });
    items.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    const unreadCount = items.filter(i => !i.is_read).length;
    res.json({ ok: true, notifications: items, unread_count: unreadCount });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب الإشعارات' });
  }
});

app.get('/api/notifications/unread_count', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    const snap = await db.ref(`notifications/${userId}`).once('value');
    let count = 0;
    snap.forEach(child => {
      const v = child.val();
      if (!v.is_read) count++;
    });
    res.json({ ok: true, unread_count: count });
  } catch (error) {
    console.error('Error fetching unread notifications count:', error);
    res.status(500).json({ ok: false, error: 'فشل في جلب عدد الإشعارات' });
  }
});

app.post('/api/notifications/mark_read', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { id } = req.body || {};
  try {
    if (id) {
      await db.ref(`notifications/${userId}/${id}`).update({ is_read: true });
    } else {
      const snap = await db.ref(`notifications/${userId}`).once('value');
      const updates = {};
      snap.forEach(child => {
        const v = child.val();
        if (v && !v.is_read) updates[`${child.key}/is_read`] = true;
      });
      if (Object.keys(updates).length > 0) {
        await db.ref(`notifications/${userId}`).update(updates);
      }
    }
    res.json({ ok: true });
  } catch (error) {
    console.error('Error marking notifications read:', error);
    res.status(500).json({ ok: false });
  }
});

app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const notifId = req.params.id;
  if (!notifId) return res.status(400).json({ ok: false });
  try {
    await db.ref(`notifications/${userId}/${notifId}`).remove();
    res.json({ ok: true });
  } catch (error) {
    console.error('Error deleting notification:', error);
    res.status(500).json({ ok: false });
  }
});

app.delete('/api/notifications', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  try {
    await db.ref(`notifications/${userId}`).remove();
    res.json({ ok: true });
  } catch (error) {
    console.error('Error clearing notifications:', error);
    res.status(500).json({ ok: false, error: 'فشل في حذف الإشعارات' });
  }
});

// ---- SSE stream endpoint: يدفع تحديثات الاشعارات فورياً للعميل ----
app.get('/api/notifications/stream', requireAuth, (req, res) => {
  const userId = req.session.userId;

  // تهيئة رأس SSE
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': corsOptions.origin.includes(req.headers.origin) ? req.headers.origin : 'null',
  });
  res.write('\n');

  const notifRef = db.ref(`notifications/${userId}`);
  const chatsRef = db.ref(`chats/${userId}`);
  const friendReqRef = db.ref(`friend_requests/${userId}`);

  // دالة تجمع بيانات الإشعارات ومجموع الرسائل غير المقروءة وترسلها
  const sendCombined = async () => {
    try {
      const [notifSnap, chatsSnap, friendSnap] = await Promise.all([
        notifRef.once('value'),
        chatsRef.once('value'),
        friendReqRef.once('value')
      ]);

      const items = [];
      notifSnap.forEach(child => {
        const v = child.val();
        items.push({ id: child.key, ...v });
      });
      items.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      const unreadNotificationsCount = items.filter(i => !i.is_read).length;

      let unreadMessagesCount = 0;
      chatsSnap.forEach(child => {
        const v = child.val();
        if (v && v.unread_count) {
          unreadMessagesCount += Number(v.unread_count) || 0;
        }
      });

      let pendingFriendRequestsCount = 0;
      friendSnap.forEach(() => pendingFriendRequestsCount++);

      const payload = {
        unread_count: unreadNotificationsCount,
        notifications: items,
        unread_messages_count: unreadMessagesCount,
        pending_friend_requests_count: pendingFriendRequestsCount
      };

      res.write(`event: notifications\n`);
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
    } catch (err) {
      console.error('Error preparing SSE payload:', err);
      res.write(`event: error\n`);
      res.write(`data: ${JSON.stringify({ error: String(err) })}\n\n`);
    }
  };

  // ربط المستمعين على كلتا العقدتين: إشعارات والدردشات وطلبات الصداقة
  notifRef.on('value', sendCombined, err => {
    console.error('SSE notifications listener error:', err);
    res.write(`event: error\ndata: ${JSON.stringify({ error: String(err) })}\n\n`);
  });
  chatsRef.on('value', sendCombined, err => {
    console.error('SSE chats listener error:', err);
    res.write(`event: error\ndata: ${JSON.stringify({ error: String(err) })}\n\n`);
  });
  friendReqRef.on('value', sendCombined, err => {
    console.error('SSE friend-requests listener error:', err);
    res.write(`event: error\ndata: ${JSON.stringify({ error: String(err) })}\n\n`);
  });

  // إرسال حالة أولية مباشرة
  sendCombined();

  // تنظيف عند إغلاق الاتصال من قبل العميل
  req.on('close', () => {
    try {
      notifRef.off('value', sendCombined);
      chatsRef.off('value', sendCombined);
      friendReqRef.off('value', sendCombined);
    } catch (e) { /* ignore */ }
    res.end();
  });
});

// ---------------- Active Status Cleaner ----------------
// مهمة دورية للتحقق من المستخدمين غير النشطين
const OFFLINE_THRESHOLD = 2 * 60 * 1000; // 2 minutes

setInterval(async () => {
  try {
    const profilesRef = db.ref('profiles');
    const snapshot = await profilesRef.orderByChild('is_online').equalTo(true).once('value');
    
    if (!snapshot.exists()) return;

    const updates = {};
    const now = Date.now();

    snapshot.forEach(child => {
      const user = child.val();
      if (user.last_seen && (now - user.last_seen > OFFLINE_THRESHOLD)) {
        updates[`${child.key}/is_online`] = false;
      }
    });

    if (Object.keys(updates).length > 0) {
      await profilesRef.update(updates);
    }
  } catch (error) {
    console.error('Error in offline check interval:', error);
  }
}, 60000); // Check every minute

// ---------------- Error Handling ----------------
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(413).json({ ok: false, error: err.message });
  next(err);
});

// 2. API لتغيير كلمة المرور
app.post('/api/change-password', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const { newPassword } = req.body;

  if (!userId) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ ok: false, error: 'كلمة المرور ضعيفة' });
  }

  try {
    // التأكد من تحديث كلمة المرور للمستخدم الحالي (باستخدام uid الصحيح)
    await admin.auth().updateUser(userId, { password: newPassword });

    res.json({ ok: true, message: 'تم تحديث كلمة المرور بنجاح' });
  } catch (err) {
    console.error('Error changing password:', err);
    // تعامل مع أخطاء Firebase Auth المحتملة
    const msg = err && err.message ? err.message : 'فشل تغيير كلمة المرور';
    res.status(500).json({ ok: false, error: msg });
  }
});

// إضافة: DELETE account endpoint (باستخدام تحقق بكلمة المرور عبر Firebase REST + حذف بواسطة Admin SDK)
// يتطلب وضع متغير البيئة FIREBASE_WEB_API_KEY
const fetch = require('node-fetch'); // إذا لم يكن مثبتاً، ثبت بواسطة: npm i node-fetch@2

// استبدل مسار الحذف الموجود في server.js بهذا الكود المحسن
app.post('/api/account/delete', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  const password = (req.body && req.body.password) ? String(req.body.password) : '';

  if (!uid) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  if (!password) return res.status(400).json({ ok: false, error: 'Password required' });

  try {
    // 1. جلب بيانات المستخدم (اسم المستخدم والبريد) قبل الحذف
    const snap = await db.ref(`profiles/${uid}`).once('value');
    const profile = snap.val() || {};
    // نحتاج اسم المستخدم لنرسله للعميل ليحذفه من LocalStorage
    const usernameToDelete = profile.username; 
    
    let email = req.session.email || profile.email;
    if (!email && usernameToDelete) email = `${usernameToDelete}@trimer.io`;
    
    if (!email) return res.status(400).json({ ok: false, error: 'Email not found for user' });

    // تأكد من وجود مفتاح API في ملف .env
    const apiKey = process.env.FIREBASE_WEB_API_KEY;
    if (!apiKey) {
      console.error('FIREBASE_WEB_API_KEY not configured in .env');
      return res.status(500).json({ ok: false, error: 'Server misconfiguration' });
    }

    // 2. التحقق من كلمة المرور
    const verifyUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`;
    const resp = await fetch(verifyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, returnSecureToken: true })
    });

    if (!resp.ok) {
      return res.status(403).json({ ok: false, error: 'كلمة المرور غير صحيحة.' });
    }

    // 3. حذف المستخدم والموارد
    try {
      await admin.auth().deleteUser(uid);

      const updates = {};
      updates[`profiles/${uid}`] = null;
      updates[`chats/${uid}`] = null;
      updates[`friends/${uid}`] = null;
      updates[`notifications/${uid}`] = null;
      // تنظيف الجلسات المرتبطة
      updates[`sessions/${req.sessionID}`] = null;

      await db.ref().update(updates).catch(() => {});

      // 4. تدمير الجلسة وإرجاع اسم المستخدم المحذوف
      req.session.destroy(() => {
        // نرسل اسم المستخدم هنا
        res.json({ ok: true, message: 'Account deleted', deletedUsername: usernameToDelete });
      });

    } catch (deleteErr) {
      console.error('Error deleting user resources:', deleteErr);
      return res.status(500).json({ ok: false, error: 'Failed to delete account logic' });
    }
  } catch (err) {
    console.error('Account delete error:', err);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// ---------------- HTMX partials (used by client-side navigation) ----------------
// These endpoints return HTML fragments (partials) consumed by HTMX on the client.
// They are lightweight representations of stories/posts used for fast in-page navigation.

// helper server-side escaper
function escapeHtml(s) {
  if (!s && s !== 0) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/**
 * Partial: posts feed (HTML)
 */
app.get('/partials/posts', requireAuth, async (req, res) => {
  try {
    const postsSnap = await db.ref('posts').orderByChild('timestamp').limitToLast(50).once('value');
    const postsArr = [];
    postsSnap.forEach(child => postsArr.push(child.val()));
    postsArr.reverse();

    const profilesSnap = await db.ref('profiles').once('value');
    const profiles = profilesSnap.val() || {};

    let html = `<div id="postsFeed" class="max-w-xl mx-auto mt-6 space-y-4">`;
    postsArr.forEach(post => {
      const user = profiles[post.userId] || {};
      const username = user.username || 'مستخدم';
      const avatar = user.profile_picture_url || DEFAULT_PROFILE_PIC_URL;
      html += `
        <div class="glass-post-card p-4 rounded-xl shadow-lg" data-post-id="${post.postId}">
          <div class="flex items-start justify-between mb-3">
            <div class="flex items-center">
              <a href="/profile?userId=${post.userId}" class="avatar-with-dot">
                <img src="${avatar}" alt="${escapeHtml(username)}" class="w-10 h-10 rounded-full object-cover ml-3 border border-gray-600">
              </a>
              <div>
                <a href="/profile?userId=${post.userId}" class="text-white font-semibold hover:text-blue-400">${escapeHtml(username)}</a>
                <p class="text-gray-400 text-xs">${new Date(post.timestamp || Date.now()).toLocaleString('ar-EG')}</p>
              </div>
            </div>
            <div>
              <button class="text-gray-400 post-menu-button" onclick="togglePostMenu('${post.postId}', '${post.userId}', event, this)"><i class="fas fa-ellipsis-v"></i></button>
            </div>
          </div>
          <p class="text-gray-200 whitespace-pre-wrap">${escapeHtml(post.content || '')}</p>
        </div>
      `;
    });
    html += `</div>`;
    res.send(html);
  } catch (err) {
    console.error('partials/posts error', err);
    res.status(500).send('<div class="text-red-400 p-4">فشل في تحميل المنشورات.</div>');
  }
});

/**
 * Partial: combined chat content (posts only, families removed)
 */
app.get('/partials/chat_content', requireAuth, async (req, res) => {
  try {
    const postsSnap = await db.ref('posts').orderByChild('timestamp').limitToLast(50).once('value');
    const postsArr = [];
    postsSnap.forEach(child => postsArr.push(child.val()));
    postsArr.reverse();

    const profilesSnap = await db.ref('profiles').once('value');
    const profiles = profilesSnap.val() || {};

    let html = '';

    // Posts block
    html += `<div id="postsFeed" class="max-w-xl mx-auto mt-6 space-y-4">`;
    postsArr.forEach(post => {
      const user = profiles[post.userId] || {};
      const username = user.username || 'مستخدم';
      const avatar = user.profile_picture_url || DEFAULT_PROFILE_PIC_URL;
      html += `<div class="glass-post-card p-4 rounded-xl shadow-lg" data-post-id="${post.postId}"><div class="flex items-start justify-between mb-3"><div class="flex items-center"><a href="/profile?userId=${post.userId}" class="avatar-with-dot"><img src="${avatar}" alt="${escapeHtml(username)}" class="w-10 h-10 rounded-full object-cover ml-3 border border-gray-600"></a><div><a href="/profile?userId=${post.userId}" class="text-white font-semibold hover:text-blue-400">${escapeHtml(username)}</a><p class="text-gray-400 text-xs">${new Date(post.timestamp || Date.now()).toLocaleString('ar-EG')}</p></div></div><div><button class="text-gray-400 post-menu-button" onclick="togglePostMenu('${post.postId}', '${post.userId}', event, this)"><i class="fas fa-ellipsis-v"></i></button></div></div><p class="text-gray-200 whitespace-pre-wrap">${escapeHtml(post.content || '')}</p></div>`;
    });
    html += `</div>`;

    res.send(html);
  } catch (err) {
    console.error('partials/chat_content error', err);
    res.status(500).send('<div class="text-red-400 p-4">فشل في تحميل المحتوى.</div>');
  }
});

// ---------------- API: Reels Implementation continued (already added above) ----------------

// ---------------- Error handling & final listen ----------------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ ok: false, error: 'Server error' });
});

// ============================================================
// Additional legacy message JSON endpoint (kept for compatibility)
// ============================================================
app.get('/api/messages/:chatId', requireAuth, async (req, res) => {
  const chatId = req.params.chatId;
  const currentUserId = req.session.userId;

  try {
    // 1. إعداد مرجع الرسائل
    const messagesRef = admin.database().ref(`chats/${chatId}/messages`);

    // 2. جلب الرسائل (التعديل الأساسي هنا)
    const snapshot = await messagesRef
      .orderByChild('timestamp')
      .limitToLast(1000) 
      .once('value');

    const messages = [];
    snapshot.forEach(child => {
      messages.push({
        ...child.val(),
        messageId: child.key
      });
    });

    // 3. جلب بيانات المستخدم الآخر (لعرض الاسم والصورة في الأعلى)
    const parts = chatId.split('_');
    const otherUserId = parts[0] === currentUserId ? parts[1] : parts[0];
    
    const userSnapshot = await admin.database().ref('users/' + otherUserId).once('value');
    const otherUserData = userSnapshot.val() || {};

    // 4. إرسال البيانات كـ JSON
    res.json({
      messages: messages,
      currentUserId: currentUserId,
      otherUser: {
        username: otherUserData.username || 'مستخدم',
        avatar: otherUserData.profilePic || DEFAULT_PROFILE_PIC_URL
      }
    });

  } catch (err) {
    console.error('Error fetching json messages:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب الرسائل' });
  }
});

// ==========================================
//  نظام بث قائمة المحادثات (SSE) - kept
// ==========================================
app.get('/api/users/stream', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  console.log(`[SSE] New connection request from User: ${currentUserId}`);

  // إعداد الهيدر للبث المستمر
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': corsOptions.origin.includes(req.headers.origin) ? req.headers.origin : 'null',
  });
  res.write('\n');

  // المراجع
  const friendsRef = db.ref(`friends/${currentUserId}`);
  const myChatsRef = db.ref(`chats/${currentUserId}`);
  const profilesRef = db.ref('profiles');

  // دالة لجلب البيانات وإرسالها
  const sendFullList = async () => {
    try {
      // 1. جلب قائمة الأصدقاء
      const friendsSnap = await friendsRef.once('value');
      const friendsObj = friendsSnap.val() || {};
      const friendIds = Object.keys(friendsObj);

      console.log(`[SSE] User ${currentUserId} has ${friendIds.length} friends.`);

      if (friendIds.length === 0) {
        // إرسال مصفوفة فارغة فوراً ليعرف العميل أنه لا يوجد بيانات
        res.write(`data: ${JSON.stringify({ users: [] })}\n\n`);
        return;
      }

      // 2. جلب المحادثات
      const chatsSnap = await myChatsRef.once('value');
      const allChats = chatsSnap.val() || {};

      // 3. جلب البروفايلات (بشكل متوازي لتسريع العملية)
      const profilePromises = friendIds.map(id => profilesRef.child(id).once('value'));
      const profileSnapshots = await Promise.all(profilePromises);
      
      const usersList = [];
      
      profileSnapshots.forEach(snap => {
        const user = snap.val();
        if (user && user.id) {
            const chatSummary = allChats[user.id] || {};
            let lastMessage = null;
            
            if (chatSummary.last_message_content) {
                lastMessage = {
                    content: chatSummary.last_message_content,
                    timestamp: chatSummary.last_message_timestamp,
                    senderId: chatSummary.last_message_sender_id
                };
            }

            usersList.push({
                id: user.id,
                username: user.username,
                full_name: user.full_name,
                profile_picture_url: user.profile_picture_url || DEFAULT_PROFILE_PIC_URL,
                is_verified: !!user.is_verified,
                last_message: lastMessage,
                unread_count: chatSummary.unread_count || 0,
                is_online: !!user.is_online
            });
        }
      });

      console.log(`[SSE] Sending ${usersList.length} users to client.`);
      
      // 4. الإرسال (تأكد من وجود \n\n في النهاية)
      res.write(`data: ${JSON.stringify({ users: usersList })}\n\n`);

    } catch (error) {
      console.error('[SSE] Error inside sendFullList:', error);
      // إرسال حدث خطأ للعميل ليعرف أن هناك مشكلة
      res.write(`event: error\ndata: ${JSON.stringify({ error: error.message })}\n\n`);
    }
  };

  // إرسال البيانات فوراً
  await sendFullList();

  // إعداد المستمعين (Listeners)
  const onDataChange = () => {
      // console.log('[SSE] Database changed, updating client...');
      sendFullList();
  };

  myChatsRef.on('value', onDataChange);
  // تحديث عند تغير حالة الأصدقاء (إضافة/حذف)
  friendsRef.on('child_added', onDataChange);
  friendsRef.on('child_removed', onDataChange);

  // تحديث دوري (Heartbeat) كل 60 ثانية للحفاظ على الاتصال وتحديث حالة الأونلاين
  const keepAlive = setInterval(() => {
    // console.log('[SSE] Keep-alive ping');
    sendFullList(); 
  }, 60000);

  req.on('close', () => {
    console.log(`[SSE] Connection closed for User: ${currentUserId}`);
    myChatsRef.off('value', onDataChange);
    friendsRef.off('child_added', onDataChange);
    friendsRef.off('child_removed', onDataChange);
    clearInterval(keepAlive);
    res.end();
  });
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
