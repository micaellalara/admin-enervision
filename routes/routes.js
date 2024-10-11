const express = require('express');
const router = express.Router();
const authenticateToken = require('../middleware/auth');
const upload = require('../middleware/upload');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Post = require('../model/posts');
const Admin = require('../model/admins');
const User = require('../model/users');
const UserProfile = require('../model/profile.model');
const Appliance = require('../model/appliances.model');

router.get('/', (req, res) => {
    res.render('home');
});

router.get('/register', (req, res) => {
    res.render('register');
});

router.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const existingAdmin = await Admin.findOne({ email });
        if (existingAdmin) {
            return res.render('register', { errorMessage: 'Email already exists' });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z]).{6,}$/;
        if (!passwordRegex.test(password)) {
            return res.render('register', { errorMessage: 'Password must be at least 6 characters long and contain at least one uppercase and one lowercase letter' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const newAdmin = new Admin({ name, email, password: hashedPassword });
        await newAdmin.save();
        console.log('Admin registered successfully');

        res.redirect('/login');
    } catch (error) {
        console.error('Error registering admin:', error);
        res.render('register', { errorMessage: 'Server error: ' + error.message });
    }
});

router.get('/login', (req, res) => {
    res.render('login');
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.render('login', { errorMessage: 'Admin not found' });
        }

        const isPasswordValid = await bcrypt.compare(password, admin.password);
        if (!isPasswordValid) {
            return res.render('login', { errorMessage: 'Invalid password' });
        }

        const payload = { admin: { id: admin.id } };
        const jwtSecret = process.env.JWT_SECRET || "4715aed3c946f7b0a38e6b534a9583628d84e96d10fbc04700770d572af3dce43625dd";
        jwt.sign(payload, jwtSecret, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.cookie('token', token, { httpOnly: true });
            res.redirect('/dashboard');
        });
    } catch (error) {
        console.error('Error logging in admin:', error);
        res.render('login', { errorMessage: 'Server error' });
    }
});

router.get('/dashboard', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.admin.id).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        const users = await User.find();
        const userIds = users.map(user => user._id);
        const userProfiles = await UserProfile.find({ userId: { $in: userIds } });

        const postsByUser = await Post.aggregate([
            { $match: { userId: { $in: userIds } } },
            { $group: { _id: "$userId", postCount: { $sum: 1 } } }
        ]);

        const usersWithOccupationAndPosts = users.map(user => {
            const profile = userProfiles.find(p => p.userId.equals(user._id));
            const userPosts = postsByUser.find(post => post._id.equals(user._id));
            return {
                id: user._id,
                username: user.username,
                kwhRate: user.kwhRate,
                email: user.email,
                role: user.role,
                status: user.status,
                createdAt: user.createdAt,
                occupation: profile ? profile.occupation : 'Not specified',
                postCount: userPosts ? userPosts.postCount : 0
            };
        });

        const today = new Date();
        const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        const endOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);

        const usersRegisteredToday = await User.countDocuments({
            createdAt: { $gte: startOfToday, $lt: endOfToday }
        });

        const totalUsers = await User.countDocuments();
        const postsAddedToday = await Post.countDocuments({
            createdAt: { $gte: startOfToday, $lt: endOfToday }
        });

        const monthlyRegisteredUsers = await User.aggregate([
            { $group: { _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } }, count: { $sum: 1 } } },
            { $sort: { _id: 1 } }
        ]);

        const months = monthlyRegisteredUsers.map(entry => entry._id);
        const userCounts = monthlyRegisteredUsers.map(entry => entry.count);

        res.render('dashboard', {
            admin,
            users: usersWithOccupationAndPosts,
            usersRegisteredToday,
            totalUsers,
            postsAddedToday,
            months,
            userCounts
        });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Server error');
    }
});

router.get('/userposts', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.admin.id).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        const searchTerm = req.query.username || '';
        const users = await User.find({ username: { $regex: searchTerm, $options: 'i' } });
        const userIds = users.map(user => user._id);

        const postsByUsers = await Post.find({ userId: { $in: userIds } }).populate('userId', 'username uploadPhoto');

        const usersWithPosts = users.map(user => {
            const userPosts = postsByUsers.filter(post => post.userId.equals(user._id));
            return {
                id: user._id,
                username: user.username,
                uploadPhoto: user.uploadPhoto,
                posts: userPosts
            };
        });

        res.render('userposts', {
            admin,
            usersWithPosts,
            searchTerm
        });
    } catch (error) {
        console.error('Error fetching user posts:', error);
        res.status(500).send('Server error');
    }
});

router.post('/flagPost/:postId', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.postId;
        const post = await Post.findById(postId);
        
        if (!post) {
            return res.status(404).send('Post not found');
        }

        post.flagged = true;
        await post.save();
        
        res.redirect('/userposts');
    } catch (error) {
        console.error('Error flagging post:', error);
        res.status(500).send('Server error');
    }
});

router.post('/deletePost/:postId', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.postId;
        const post = await Post.findById(postId);
        
        if (!post) {
            return res.status(404).send('Post not found');
        }

        await Post.findByIdAndDelete(postId);
        res.redirect('/userposts');
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).send('Server error');
    }
});

router.get('/profile', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.admin.id).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        res.render('profile', { admin });
    } catch (error) {
        console.error('Error fetching admin:', error);
        res.status(500).send('Server error');
    }
});

router.post('/profile', authenticateToken, upload.single('picture'), async (req, res) => {
    try {
        const { name, bio } = req.body;
        const picture = req.file ? '/images/' + req.file.filename : null;
        const updatedFields = { name, bio };
        if (picture) {
            updatedFields.picture = picture;
        }

        const admin = await Admin.findByIdAndUpdate(req.admin.id, updatedFields, { new: true });
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        res.render('profile', { admin, successMessage: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating admin profile:', error);
        res.status(500).send('Server error');
    }
});

router.get('/user-profiles', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.admin.id).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        const searchTerm = req.query.username || '';
        const users = await User.find({ username: { $regex: searchTerm, $options: 'i' } });
        
        res.render('user-profiles', { admin, users, searchTerm });
    } catch (error) {
        console.error('Error fetching user profiles:', error);
        res.status(500).send('Server error');
    }
});

router.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

module.exports = router;
