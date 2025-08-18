// server.js
const express = require('express');
const path = require('path');
const session = require('express-session');
const admin = require('firebase-admin');
const { getAuth } = require('firebase-admin/auth');
const { getDatabase } = require('firebase-admin/database');

const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
// لم نعد بحاجة إلى مكتبة 'fs' لأننا لا نتعامل مع الملفات المحلية

// Cloudinary Configuration using Environment Variables
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

// Multer setup for file uploads using Cloudinary Storage
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: (req, file) => {
        // تحديد المجلد بناءً على المسار
        if (req.originalUrl.includes('/register')) {
            return 'profile_pics';
        } else if (req.originalUrl.includes('/messages/send')) {
            return 'chat_media';
        }
        return 'general';
    },
    format: async (req, file) => 'jpg', // يمكنك تغيير التنسيق حسب حاجتك
    public_id: (req, file) => Date.now() + '-' + file.originalname,
  },
});

const upload = multer({ storage: storage });

// Load service account key from environment variable
const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_KEY);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://trimer-4081b-default-rtdb.firebaseio.com",
});

const firebaseAuth = getAuth();
const db = getDatabase();

const app = express();
const port = 3000;

// ---------------- Middleware ----------------
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: 'a-firebase-secret-key-is-better',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// ---------------- Authentication helper ----------------
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  return res.redirect('/login');
}

// ---------------- Routes: pages ----------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'splash.html'));
});

app.get('/check-status', (req, res) => {
  if (req.session && req.session.userId) {
    res.redirect('/chat_list');
  } else {
    res.redirect('/login');
  }
});

app.get('/chat_list', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'chat_list.html'));
});

app.get('/chat.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'chat.html'));
});
app.get('/chat', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'chat.html'));
});

app.get('/profile', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'profile.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

// ---------------- Auth Routes ----------------
app.post('/login', async (req, res) => {
  const { username } = req.body;
  try {
    const email = `${username}@trimer.io`;
    const userRecord = await firebaseAuth.getUserByEmail(email);
    req.session.userId = userRecord.uid;
    req.session.email = userRecord.email;
    res.redirect('/chat_list');
  } catch (error) {
    console.error('Login error:', error.message);
    const errorMessage = 'Invalid username or password.';
    res.redirect('/login?error=' + encodeURIComponent(errorMessage));
  }
});

app.post('/register', upload.single('profile_picture'), async (req, res) => {
  const { username, password } = req.body;
  let profile_picture_url = cloudinary.url('default_profile.png', { secure: true });

  try {
    if (!username || !password) {
        return res.redirect('/register?error=' + encodeURIComponent('اسم المستخدم وكلمة المرور مطلوبان.'));
    }

    const email = `${username}@trimer.io`;

    if (req.file) {
      // no need to manually upload or delete from local disk
      profile_picture_url = req.file.path; // CloudinaryStorage saves the public URL to req.file.path
    }

    const userRecord = await firebaseAuth.createUser({
      email: email,
      password: password,
      displayName: username,
      photoURL: profile_picture_url
    });

    const profileData = {
      id: userRecord.uid,
      username: username,
      full_name: username,
      email: email,
      profile_picture_url: profile_picture_url,
      is_online: false,
      is_verified: false,
    };
    await db.ref('profiles/' + userRecord.uid).set(profileData);

    req.session.userId = userRecord.uid;
    req.session.email = email;
    res.redirect('/chat_list');
  } catch (error) {
    console.error('Registration Error:', error.message);
    res.redirect('/register?error=' + encodeURIComponent(error.message));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// ---------------- API: Realtime Database backend ----------------

app.get('/api/profile', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  const requestedUserId = req.query.user_id || currentUserId;

  try {
    const [profileSnapshot, userSnapshot] = await Promise.all([
      db.ref('profiles/' + requestedUserId).once('value'),
      db.ref('users/' + requestedUserId).once('value')
    ]);
    
    const profileData = profileSnapshot.val() || {};
    const userData = userSnapshot.val() || {};

    const fullProfile = {
      id: requestedUserId,
      username: profileData.username || userData.username || userData.displayName || '',
      full_name: profileData.full_name || userData.full_name || userData.displayName || '',
      email: profileData.email || userData.email || '',
      profile_picture_url: profileData.profile_picture_url || userData.profile_picture_url || cloudinary.url('default_profile.png', { secure: true }),
      is_online: !!(profileData.is_online || userData.is_online),
      is_verified: !!(profileData.is_verified || userData.is_verified)
    };

    res.json(fullProfile);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

app.get('/api/chat_list', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  try {
    const [profilesSnapshot, usersSnapshot, messagesSnapshot] = await Promise.all([
      db.ref('profiles').once('value'),
      db.ref('users').once('value'),
      db.ref('messages').once('value')
    ]);

    const profiles = profilesSnapshot.val() || {};
    const users = usersSnapshot.val() || {};
    const allMessages = messagesSnapshot.val() || {};

    const map = {};

    Object.keys(users).forEach(uid => {
      map[uid] = {
        id: uid,
        username: users[uid].username || users[uid].displayName || '',
        full_name: users[uid].full_name || users[uid].displayName || '',
        profile_picture_url: users[uid].profile_picture_url || users[uid].photoURL || cloudinary.url('default_profile.png', { secure: true }),
        is_online: !!users[uid].is_online,
        is_verified: !!users[uid].is_verified
      };
    });

    Object.keys(profiles).forEach(uid => {
      map[uid] = {
        id: uid,
        username: profiles[uid].username || (map[uid] && map[uid].username) || '',
        full_name: profiles[uid].full_name || (map[uid] && map[uid].full_name) || '',
        profile_picture_url: profiles[uid].profile_picture_url || (map[uid] && map[uid].profile_picture_url) || cloudinary.url('default_profile.png', { secure: true }),
        is_online: !!profiles[uid].is_online,
        is_verified: !!profiles[uid].is_verified
      };
    });

    const results = [];
    for (const uid of Object.keys(map)) {
      if (uid === currentUserId) continue;

      const p = map[uid];

      let lastMessage = null;
      Object.values(allMessages).forEach(msg => {
        if (!msg) return;
        if ((msg.sender_id === currentUserId && msg.receiver_id === uid) ||
            (msg.sender_id === uid && msg.receiver_id === currentUserId)) {
          if (!lastMessage || new Date(msg.created_at) > new Date(lastMessage.created_at)) {
            lastMessage = msg;
          }
        }
      });

      const last = lastMessage;
      const is_new = !!(last && last.sender_id !== currentUserId && !last.is_read);

      results.push({
        user: {
          id: p.id,
          username: p.username,
          full_name: p.full_name || null,
          profile_picture_url: p.profile_picture_url || cloudinary.url('default_profile.png', { secure: true }),
          is_online: !!p.is_online,
          is_verified: !!p.is_verified
        },
        last_message: last ? last.content : '',
        last_time: last ? last.created_at : null,
        is_new: is_new
      });
    }

    results.sort((a, b) => {
      if (a.is_new === b.is_new) {
        const at = a.last_time ? new Date(a.last_time).getTime() : 0;
        const bt = b.last_time ? new Date(b.last_time).getTime() : 0;
        if (at === bt) {
          const an = (a.user.username || '').toLowerCase();
          const bn = (b.user.username || '').toLowerCase();
          return an < bn ? -1 : (an > bn ? 1 : 0);
        }
        return bt - at;
      }
      return a.is_new ? -1 : 1;
    });

    res.json(results);
  } catch (err) {
    console.error('/api/chat_list error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/messages/:other_id', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  const otherId = req.params.other_id;

  try {
    const messagesSnapshot = await db.ref('messages').orderByChild('created_at').once('value');
    const allMessages = messagesSnapshot.val() || {};

    const chatMessages = Object.values(allMessages).filter(msg =>
      (msg.sender_id === currentUserId && msg.receiver_id === otherId) ||
      (msg.sender_id === otherId && msg.receiver_id === currentUserId)
    );

    res.json(chatMessages);
  } catch (err) {
    console.error('/api/messages/:other_id error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/messages/send', upload.single('media'), requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  const { other_id, content, replied_to_id, replied_to_content, replied_to_sender } = req.body;
  let media_url = null;
  let media_type = 'text';

  try {
    if (req.file) {
      // The file has been uploaded to Cloudinary by multer
      media_url = req.file.path;
      media_type = req.file.resource_type;
    }

    if (!other_id || (!content && !media_url)) {
      return res.status(400).json({ error: 'other_id and content or media are required' });
    }

    const messagesRef = db.ref('messages');
    const newMessageRef = messagesRef.push();

    const payload = {
      id: newMessageRef.key,
      sender_id: currentUserId,
      receiver_id: other_id,
      content: content || '',
      created_at: new Date().toISOString(),
      is_read: false,
      media_url: media_url,
      media_type: media_type
    };

    if (replied_to_id) {
        payload.replied_to_id = replied_to_id;
        payload.replied_to_content = replied_to_content;
        payload.replied_to_sender = replied_to_sender;
    }

    await newMessageRef.set(payload);
    res.json({ ok: true, message: payload });
  } catch (err) {
    console.error('/api/messages/send error', err);
    res.status(500).json({ error: 'Server error' });
  }
});


app.post('/api/mark_read', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  const { other_id } = req.body;
  if (!other_id) return res.status(400).json({ error: 'other_id is required' });

  try {
    const messagesSnapshot = await db.ref('messages').orderByChild('receiver_id').equalTo(currentUserId).once('value');
    const messagesToUpdate = messagesSnapshot.val() || {};

    const updates = {};
    let updatedCount = 0;

    Object.keys(messagesToUpdate).forEach(key => {
      const msg = messagesToUpdate[key];
      if (msg.sender_id === other_id && !msg.is_read) {
        updates[`/messages/${key}/is_read`] = true;
        updatedCount++;
      }
    });

    if (updatedCount > 0) {
      await db.ref().update(updates);
    }

    res.json({ ok: true, updated: updatedCount });
  } catch (err) {
    console.error('/api/mark_read error', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// New search endpoint
app.get('/api/users/search', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  const { query } = req.query;
  if (!query) {
    return res.status(400).json({ error: 'Search query is required' });
  }

  const searchQuery = query.toLowerCase();

  try {
    const [profilesSnapshot, usersSnapshot] = await Promise.all([
      db.ref('profiles').once('value'),
      db.ref('users').once('value')
    ]);
    const profiles = profilesSnapshot.val() || {};
    const users = usersSnapshot.val() || {};

    const map = {};
    const foundUsers = [];

    // Combine data from 'users' and 'profiles'
    Object.keys(users).forEach(uid => {
      map[uid] = {
        uid: uid,
        username: users[uid].username || users[uid].displayName || '',
        full_name: users[uid].full_name || users[uid].displayName || '',
        profile_picture_url: users[uid].profile_picture_url || users[uid].photoURL || cloudinary.url('default_profile.png', { secure: true }),
        is_online: !!users[uid].is_online,
        is_verified: !!users[uid].is_verified
      };
    });

    Object.keys(profiles).forEach(uid => {
      map[uid] = {
        uid: uid,
        username: profiles[uid].username || (map[uid] && map[uid].username) || '',
        full_name: profiles[uid].full_name || (map[uid] && map[uid].full_name) || '',
        profile_picture_url: profiles[uid].profile_picture_url || (map[uid] && map[uid].profile_picture_url) || cloudinary.url('default_profile.png', { secure: true }),
        is_online: !!profiles[uid].is_online,
        is_verified: !!profiles[uid].is_verified
      };
    });

    // Filter users based on search query
    Object.values(map).forEach(user => {
      if (user.uid === currentUserId) return;
      if (
        (user.username && user.username.toLowerCase().includes(searchQuery)) ||
        (user.full_name && user.full_name.toLowerCase().includes(searchQuery))
      ) {
        foundUsers.push(user);
      }
    });

    res.status(200).json(foundUsers);
  } catch (error) {
    console.error("Error searching users:", error);
    res.status(500).json({ error: 'Failed to search users' });
  }
});


app.get('/api/users', requireAuth, async (req, res) => {
  const currentUserId = req.session.userId;
  try {
    const [profilesSnapshot, usersSnapshot] = await Promise.all([
      db.ref('profiles').once('value'),
      db.ref('users').once('value')
    ]);
    const profiles = profilesSnapshot.val() || {};
    const users = usersSnapshot.val() || {};

    const map = {};

    Object.keys(users).forEach(uid => {
      map[uid] = {
        uid: uid,
        username: users[uid].username || users[uid].displayName || '',
        full_name: users[uid].full_name || users[uid].displayName || '',
        profile_picture_url: users[uid].profile_picture_url || users[uid].photoURL || cloudinary.url('default_profile.png', { secure: true }),
        is_online: !!users[uid].is_online,
        is_verified: !!users[uid].is_verified
      };
    });

    Object.keys(profiles).forEach(uid => {
      map[uid] = {
        uid: uid,
        username: profiles[uid].username || (map[uid] && map[uid].username) || '',
        full_name: profiles[uid].full_name || (map[uid] && map[uid].full_name) || '',
        profile_picture_url: profiles[uid].profile_picture_url || (map[uid] && map[uid].profile_picture_url) || cloudinary.url('default_profile.png', { secure: true }),
        is_online: !!profiles[uid].is_online,
        is_verified: !!profiles[uid].is_verified
      };
    });

    const usersList = Object.keys(map)
      .filter(uid => uid !== currentUserId)
      .map(uid => ({ uid, ...map[uid] }));

    res.status(200).json(usersList);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/debug/session', (req, res) => {
  res.json({
    ok: true,
    hasSession: !!(req.session && req.session.userId),
    session: req.session || null,
    cookies: req.headers.cookie || null
  });
});

app.get('/api/debug/raw_profiles', requireAuth, async (req, res) => {
  try {
    const snap = await db.ref('profiles').once('value');
    res.json({ ok: true, count: snap.numChildren(), data: snap.val() });
  } catch (err) {
    console.error('raw_profiles error', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/debug/raw_users', requireAuth, async (req, res) => {
  try {
    const snap = await db.ref('users').once('value');
    res.json({ ok: true, count: snap.numChildren(), data: snap.val() });
  } catch (err) {
    console.error('raw_users error', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});