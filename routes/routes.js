const express = require('express');
const router = express.Router();
const authenticateToken = require('../middleware/auth');
const upload = require('../middleware/upload');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Post = require('../model/posts');
const Suggestion = require('../model/suggestions.model');
const Admin = require('../model/admins');
const User = require('../model/users');
const UserProfile = require('../model/profile.model');
const Appliance = require('../model/appliances.model');
const FAQ = require('../model/faqs.model');
const Chat = require('../model/chats.model');
const Device = require('../model/devices');
const EnergyProvider = require('../model/energy_provider.model');
const { check, validationResult } = require('express-validator');

router.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});

router.get('/', (req, res) => {
    res.render('home');
});

router.get('/register', (req, res) => {
    res.render('register', { errorMessage: null });
});

router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.render('register', { errorMessage: 'Email already exists' });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z]).{6,}$/;
        if (!passwordRegex.test(password)) {
            return res.render('register', { errorMessage: 'Password must be at least 6 characters long and contain at least one uppercase and one lowercase letter' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newAdmin = new User({
            username: username,
            email: email,
            password: hashedPassword,
            role: 'admin',
            kwhRate: 0,
            status: 'active',
            postCount: 0,
        });

        await newAdmin.save();

        console.log('Admin registered successfully');

        res.redirect('/login');
    } catch (error) {
        console.error('Error registering admin:', error);
        res.render('register', { errorMessage: 'Server error' });
    }
});


router.get('/login', (req, res) => {
    res.render('login', { errorMessage: null });
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('login', { errorMessage: 'Email not found' });
        }



        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.render('login', { errorMessage: 'Invalid password' });
        }

        if (user.role !== 'admin') {
            return res.render('login', { errorMessage: 'You do not have admin access' });
        }

        const payload = { user: { userId: user._id, role: user.role } };

        const jwtSecret = process.env.JWT_SECRET || "4715aed3c946f7b0a38e6b534a9583628d84e96d10fbc04700770d572af3dce43625dd";

        jwt.sign(payload, jwtSecret, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;

            res.cookie('token', token, { httpOnly: true });
            res.redirect('/dashboard');
        });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.render('login', { errorMessage: 'Server error' });
    }
});


router.get('/api/average-appliances', async (req, res) => {
    const { start, end } = req.query;

    if (!start || !end) {
        return res.status(400).json({ error: "Start and end dates are required." });
    }

    try {
        const applianceData = await User.aggregate([
            {
                $match: {
                    createdAt: { $gte: new Date(start), $lte: new Date(end) }
                }
            },
            {
                $project: {
                    day: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
                    appliancesCount: { $size: "$appliances" }
                }
            },
            {
                $group: {
                    _id: "$day",
                    totalAppliances: { $sum: "$appliancesCount" },
                    userCount: { $sum: 1 }
                }
            },
            {
                $project: {
                    date: "$_id",
                    averageAppliances: {
                        $cond: {
                            if: { $gt: ["$userCount", 0] },
                            then: { $divide: ["$totalAppliances", "$userCount"] },
                            else: 0
                        }
                    }
                }
            },
            {
                $sort: { date: 1 }
            }
        ]);

        const totalAppliancesInDateRange = applianceData.reduce((acc, entry) => acc + entry.totalAppliances, 0);

        const today = new Date();
        const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        const endOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);

        const appliancesAddedTodayData = await User.aggregate([
            {
                $match: {
                    createdAt: { $gte: startOfToday, $lt: endOfToday }
                }
            },
            {
                $project: {
                    totalAppliances: { $size: "$appliances" }
                }
            },
            {
                $group: {
                    _id: null,
                    total: { $sum: "$totalAppliances" }
                }
            }
        ]);

        const appliancesAddedTodayCount = appliancesAddedTodayData[0]?.total || 0;

        const totalAppliancesData = await User.aggregate([
            {
                $project: {
                    totalAppliances: { $size: "$appliances" }
                }
            },
            {
                $group: {
                    _id: null,
                    total: { $sum: "$totalAppliances" }
                }
            }
        ]);

        const totalAppliances = totalAppliancesData[0]?.total || 0;

        res.json({
            applianceDays: applianceData.map(entry => entry.date),
            averageApplianceCounts: applianceData.map(entry => entry.averageAppliances),
            totalAppliances: totalAppliancesInDateRange,
            appliancesTodayCount: appliancesAddedTodayCount,
            totalAppliancesStored: totalAppliances
        });
    } catch (error) {
        console.error("Error fetching average appliances data:", error);
        res.status(500).send("Internal Server Error");
    }
});

router.get('/dashboard', authenticateToken, async (req, res) => {
    try {
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) return res.status(404).send('Admin not found');

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
                communityGuidelinesAccepted: user.communityGuidelinesAccepted,
                username: user.username,
                kwhRate: user.kwhRate,
                email: user.email,
                role: user.role,
                status: user.status,
                createdAt: user.createdAt,
                occupation: profile ? profile.occupation : 'Not specified',
                postCount: userPosts ? userPosts.postCount : 0,
                applianceCount: user.appliances.length
            };
        });

        const today = new Date();
        const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        const endOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);

        const usersRegisteredToday = await User.countDocuments({ createdAt: { $gte: startOfToday, $lt: endOfToday } });
        const totalUsers = await User.countDocuments();
        const postsAddedToday = await Post.countDocuments({ createdAt: { $gte: startOfToday, $lt: endOfToday } });

        const totalAppliancesData = await User.aggregate([
            {
                $project: {
                    totalAppliances: { $size: "$appliances" }
                }
            },
            {
                $group: {
                    _id: null,
                    total: { $sum: "$totalAppliances" }
                }
            }
        ]);

        const totalAppliances = totalAppliancesData[0]?.total || 0;

        const appliancesAddedTodayData = await User.aggregate([
            {
                $match: {
                    createdAt: { $gte: startOfToday, $lt: endOfToday }
                }
            },
            {
                $project: {
                    totalAppliances: { $size: "$appliances" }
                }
            },
            {
                $group: {
                    _id: null,
                    total: { $sum: "$totalAppliances" }
                }
            }
        ]);

        const appliancesAddedTodayCount = appliancesAddedTodayData[0]?.total || 0;

        const monthlyRegisteredUsers = await User.aggregate([
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        const months = monthlyRegisteredUsers.map(entry => entry._id);
        const userCounts = monthlyRegisteredUsers.map(entry => entry.count);

        const applianceCountsPerDay = await User.aggregate([
            {
                $project: {
                    day: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
                    appliances: { $size: "$appliances" }
                }
            },
            {
                $group: {
                    _id: "$day",
                    totalAppliances: { $sum: "$appliances" },
                    userCount: { $sum: 1 }
                }
            },
            {
                $project: {
                    date: "$_id",
                    averageAppliances: { $divide: ["$totalAppliances", "$userCount"] }
                }
            },
            { $sort: { date: 1 } }
        ]);

        const applianceDays = applianceCountsPerDay.map(entry => entry.date);
        const averageApplianceCounts = applianceCountsPerDay.map(entry => entry.averageAppliances);

        res.render('dashboard', {
            admin,
            users: usersWithOccupationAndPosts,
            usersRegisteredToday,
            totalUsers,
            postsAddedToday,
            totalAppliances,
            appliancesAddedToday: appliancesAddedTodayCount,
            months,
            userCounts,
            applianceDays,
            averageApplianceCounts,
            communityGuidelinesAccepted: users.communityGuidelinesAccepted ? 'Accepted' : 'Not Accepted',
        });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Server error');
    }
});



router.get('/userposts', authenticateToken, async (req, res) => {
    try {
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) return res.status(404).send('Admin not found');

        const searchTerm = req.query.username || '';
        const users = await User.find({ username: { $regex: searchTerm, $options: 'i' } });
        const userIds = users.map(user => user._id);

        const postsByUsers = await Post.find({ userId: { $in: userIds }, deletedAt: null }).populate('userId', 'username uploadPhoto');

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
router.post('/createPost', authenticateToken, async (req, res) => {
    const { title, description, tags } = req.body;

    try {
        const userId = req.user.userId;

        if (!userId) {
            return res.status(400).send('User ID is required');
        }

        if (!title || !description || !tags) {
            return res.status(400).send('Title, description, and tags are required');
        }

        const newPost = new Post({
            title,
            description,
            tags,
            userId,
        });

        await newPost.save();
        res.status(201).json({ success: true, message: 'Post created successfully' });
    } catch (err) {
        console.error('Error creating post:', err);
        res.status(500).send('Server Error');
    }
});



router.post('/flagPost/:postId', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.postId;
        const post = await Post.findById(postId);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        post.flagged = true;
        await post.save();

        res.json({ success: true, postId: postId });
    } catch (error) {
        console.error('Error flagging post:', error);
        res.status(500).json({ error: 'Server error' });
    }
});



router.post('/deletePost/:postId', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.postId;
        const post = await Post.findById(postId);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        post.deletedAt = new Date();


        await post.save();
        res.json({ success: true, postId: postId });
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ error: 'Server error' });
    }
});



router.get('/flaggedPosts', authenticateToken, async (req, res) => {
    try {

        const flaggedPosts = await Post.find({ flagged: true }).populate('userId', 'username uploadPhoto');
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }
        res.render('flaggedPosts', {
            flaggedPosts: flaggedPosts,
            admin: admin
        });
    } catch (error) {
        console.error('Error fetching flagged posts:', error);
        res.status(500).send('Server error');
    }
});

router.get('/deletedPosts', authenticateToken, async (req, res) => {
    try {
        const deletedPosts = await Post.find({ deletedAt: { $ne: null } })
            .populate('userId', 'username uploadPhoto');

        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }


        deletedPosts.forEach(post => {
            if (!post.userId) {
                console.warn(`Post ${post._id} does not have a valid userId.`);
            }
        });

        res.render('deletedPosts', {
            deletedPosts,
            admin
        });
    } catch (error) {
        console.error('Error fetching deleted posts:', error);
        res.status(500).send('Server error');
    }
});


router.post('/restorePost/:postId', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.postId;
        const post = await Post.findById(postId);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        if (!post.deletedAt) {
            return res.status(400).json({ error: 'Post is not deleted' });
        }

        post.deletedAt = null;
        await post.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error restoring post:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

router.post('/unflagPost/:postId', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.postId;
        const post = await Post.findById(postId);

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        if (!post.flagged) {
            return res.status(400).json({ error: 'Post is not flagged' });
        }

        post.flagged = false;
        await post.save();

        res.json({ success: true });
    } catch (error) {
        console.error('Error unflagging post:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

router.get('/posts-with-suggestions', authenticateToken, async (req, res) => {
    try {
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }


        const users = await User.find().select('username _id').lean();

        const posts = await Post.find()
            .populate({
                path: 'suggestions',
                model: 'Suggestion',
                select: 'suggestionText suggestionDate userId',
                populate: {
                    path: 'userId',
                    model: 'User',
                    select: 'username',
                },
            })
            .populate({
                path: 'userId',
                model: 'User',
                select: 'username',
            })
            .lean();

        res.render('postsWithSuggestions', { users, posts, admin });
    } catch (error) {
        console.error('Error fetching posts with suggestions:', error);
        res.status(500).send('Server Error');
    }
});

router.post('/addSuggestion/:postId', authenticateToken, async (req, res) => {
    const { suggestionText } = req.body;
    const postId = req.params.postId;

    try {
        console.log('Authenticated user:', req.user);

        if (!req.user || !req.user.userId) {
            return res.status(400).send('User ID is missing');
        }

        const admin = await User.findById(req.user.userId).select('-password'); 
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        const newSuggestion = new Suggestion({
            suggestionText,
            postId,
            userId: req.user.userId,  
            suggestionDate: new Date(),
            deletedAt: null,
        });

        await newSuggestion.save();

        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).send('Post not found');
        }

        post.suggestions.push(newSuggestion._id);
        await post.save();

        res.redirect(`/posts-with-suggestions`);
    } catch (error) {
        console.error('Error adding suggestion:', error);
        res.status(500).send('Internal Server Error');
    }
});



router.get('/profile', authenticateToken, async (req, res) => {
    try {
        const admin = await User.findById(req.user.userId).select('-password');
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
        const { username } = req.body;
        const picture = req.file ? '/images/' + req.file.filename : null;

        const updatedFields = { username };
        if (picture) {
            updatedFields.picture = picture;  
        }

        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        await User.findByIdAndUpdate(req.user.userId, updatedFields, { new: true });

        const updatedAdmin = await User.findById(req.user.userId).select('-password');

        res.render('profile', { admin: updatedAdmin, successMessage: 'Profile updated successfully' });

    } catch (error) {
        console.error('Error updating admin profile:', error);
        res.status(500).send('Server error');
    }
});


router.get('/user-profiles', authenticateToken, async (req, res) => {
    try {
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }
        const searchTerm = req.query.username || '';
        const currentPage = parseInt(req.query.page) || 1;
        const usersPerPage = 5;

        const users = await User.find({
            username: { $regex: searchTerm, $options: 'i' }
        }).skip((currentPage - 1) * usersPerPage).limit(usersPerPage);

        const totalCount = await User.countDocuments({
            username: { $regex: searchTerm, $options: 'i' }
        });
        const totalPages = Math.ceil(totalCount / usersPerPage);

        const userIds = users.map(user => user._id);
        const userProfiles = await UserProfile.find({ userId: { $in: userIds } });

        const postsByUser = await Post.aggregate([
            { $match: { userId: { $in: userIds } } },
            { $group: { _id: "$userId", postCount: { $sum: 1 } } }
        ]);

        const usersWithDetails = users.map(user => {
            const profile = userProfiles.find(p => p.userId.equals(user._id));
            const userPosts = postsByUser.find(post => post._id.equals(user._id));

            return {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                status: user.status,
                name: profile ? profile.name : 'Not specified',
                occupation: profile ? profile.occupation : 'Not specified',
                postCount: userPosts ? userPosts.postCount : 0
            };
        });

        const startIndex = (currentPage - 1) * usersPerPage + 1;
        const endIndex = Math.min(startIndex + users.length - 1, totalCount);

        res.render('userProfiles', {
            admin,
            users: usersWithDetails,
            searchTerm,
            totalCount,
            currentPage,
            totalPages,
            startIndex,
            endIndex
        });
    } catch (error) {
        console.error('Error fetching user profiles:', error);
        res.status(500).send('Server error');
    }
});


router.get('/user/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).populate('appliances');

        const profile = await UserProfile.findOne({ userId: user._id });
        const userPosts = await Post.aggregate([
            { $match: { userId: user._id } },
            { $group: { _id: "$userId", postCount: { $sum: 1 } } }
        ]);

        const applianceCount = user.appliances.length;

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({
            id: user._id,
            username: user.username,
            email: user.email,
            status: user.status,
            kwhRate: user.kwhRate,
            name: profile ? profile.name : 'Not specified',
            mobileNumber: profile ? profile.mobileNumber : 'Not specified',
            occupation: profile ? profile.occupation : 'Not specified',
            address: profile ? profile.address : 'Not specified',
            banDate: profile ? profile.banDate : null,
            communityGuidelinesAccepted: user.communityGuidelinesAccepted,
            postCount: userPosts.length > 0 ? userPosts[0].postCount : 0,
            applianceCount
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

router.get('/profile/edit/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        const profile = await UserProfile.findOne({ userId: user._id });

        if (!user || !profile) {
            return res.status(404).send('User not found');
        }

        res.render('editProfile', { user, profile });
    } catch (error) {
        console.error('Error fetching user for edit:', error);
        res.status(500).send('Server error');
    }
});

router.post('/user-profiles/deleteUser/:id', async (req, res) => {
    const userId = req.params.id;

    try {
        const postCount = await Post.countDocuments({ userId });
        const applianceCount = await Appliance.countDocuments({ userId });
        const suggestionCount = await Suggestion.countDocuments({ userId });

        await User.findByIdAndUpdate(userId, { status: 'deleted' });

        await Post.updateMany({ userId }, { status: 'deleted' });
        await Appliance.updateMany({ userId }, { status: 'deleted' });
        await Suggestion.updateMany({ userId }, { status: 'deleted' });
        console.log(`User deleted. Posts deleted: ${postCount}, Appliances deleted: ${applianceCount}, Suggestions deleted: ${suggestionCount}.`);

        res.redirect('/user-profiles');
    } catch (error) {
        console.error('Error soft deleting user and related data:', error);
        res.redirect('/user-profiles');
    }
});


router.post('/user-profiles/banUser/:id', async (req, res) => {
    const userId = req.params.id;

    try {
        await User.findByIdAndUpdate(userId, { status: 'banned' });
        res.redirect('/user-profiles');
    } catch (error) {
        console.error('Error ban of user:', error);
        res.redirect('/user-profiles');
    }
});

router.post('/user-profiles/unbanUser/:id', async (req, res) => {
    const userId = req.params.id;
    await User.updateOne({ _id: userId }, { status: 'active' });
    res.redirect('/user-profiles');
});

router.post('/user-profiles/restoreUser/:id', async (req, res) => {
    const userId = req.params.id;

    try {
        const postCount = await Post.countDocuments({ userId, status: 'deleted' });
        const applianceCount = await Appliance.countDocuments({ userId, status: 'deleted' });
        const suggestionCount = await Suggestion.countDocuments({ userId, status: 'deleted' });

        await User.findByIdAndUpdate(userId, { status: 'active' });

        await Post.updateMany({ userId, status: 'deleted' }, { status: 'active' });
        await Appliance.updateMany({ userId, status: 'deleted' }, { status: 'active' });
        await Suggestion.updateMany({ userId, status: 'deleted' }, { status: 'active' });

        console.log(`User restored. Posts restored: ${postCount}, Appliances restored: ${applianceCount}, Suggestions restored: ${suggestionCount}.`);

        res.redirect('/user-profiles');
    } catch (error) {
        console.error('Error restoring user and related data:', error);
        res.redirect('/user-profiles');
    }
});


router.get('/faqs', authenticateToken, async (req, res) => {
    try {
        const faqs = await FAQ.find();

        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        res.render('faqs', { faqs, admin });
    } catch (err) {
        console.error('Error fetching FAQs:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.post('/faqs', authenticateToken, async (req, res) => {
    const { question, answer } = req.body;
    const newFAQ = new FAQ({ question, answer });

    try {
        const savedFAQ = await newFAQ.save();

        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        res.status(201).redirect('/faqs');
    } catch (err) {
        console.error('Error saving FAQ:', err);
        res.status(400).json({ message: 'Error saving FAQ' });
    }
});

router.put('/faqs/:id', authenticateToken, async (req, res) => {
    const { question, answer } = req.body;
    try {
        const updatedFAQ = await FAQ.findByIdAndUpdate(req.params.id, { question, answer }, { new: true });
        if (!updatedFAQ) {
            return res.status(404).send('FAQ not found');
        }
        res.redirect('/faqs');
    } catch (err) {
        console.error('Error updating FAQ:', err);
        res.status(400).json({ message: 'Error updating FAQ' });
    }
});

router.delete('/faqs/:id', authenticateToken, async (req, res) => {
    try {
        const deletedFAQ = await FAQ.findByIdAndDelete(req.params.id);
        if (!deletedFAQ) {
            return res.status(404).send('FAQ not found');
        }
        res.redirect('/faqs');
    } catch (err) {
        console.error('Error deleting FAQ:', err);
        res.status(500).json({ message: 'Server Error' });
    }
});

router.get('/chats', authenticateToken, async (req, res) => {
    try {
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        const chats = await Chat.find({})
            .populate('userId', 'username') 
            .exec();

        const formattedChats = chats.map(chat => {
            // Check if chat.userId exists before accessing its properties
            if (!chat.userId) {
                return {
                    userId: null,   // Or some default value
                    username: 'Unknown', // Default username if user is missing
                    messages: chat.messages,
                };
            }

            return {
                userId: chat.userId._id,
                username: chat.userId.username,
                messages: chat.messages,
            };
        });

        res.render('adminChats', { chats: formattedChats, admin });
    } catch (error) {
        console.error('Error fetching chats:', error);
        res.status(500).json({ message: error.message });
    }
});


router.get('/chats/:userId', authenticateToken, async (req, res) => {
    const userId = req.params.userId;

    try {
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        const chat = await Chat.findOne({ userId });
        if (!chat) {
            return res.status(404).json({ error: 'Chat not found for this user' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const allMessages = [
            ...chat.messages.map(msg => ({
                sender: msg.sender,
                message: msg.message,
                timestamp: msg.timestamp,
            })),
            ...chat.adminReplies.map(reply => ({
                sender: 'admin',
                message: reply.message,
                timestamp: reply.timestamp,
            })),
        ];

        allMessages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        if (req.xhr) {
            return res.json({ messages: allMessages, userName: user.username });
        }

        res.render('adminChats', {
            chats: allMessages,
            userName: user.username,
            admin
        });

    } catch (error) {
        console.error('Error fetching chat for user:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



router.post('/chats/:userId/reply', authenticateToken, async (req, res) => {
    const userId = req.params.userId;
    const { message } = req.body;

    if (!message || !message.trim()) {
        return res.status(400).json({ error: 'Message content is required' });
    }

    try {
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        const chat = await Chat.findOne({ 'userId': userId });
        if (!chat) {
            return res.status(404).json({ error: 'Chat not found for this user' });
        }

        const adminReply = {
            sender: 'admin',
            message: message,
            timestamp: new Date(),
        };

        chat.adminReplies.push(adminReply);

        await chat.save();

        res.status(200).json({ message: 'Reply sent successfully' });

    } catch (error) {
        console.error('Error sending reply:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/devices', authenticateToken, async (req, res) => {
    try {
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }
        const devices = await Device.find();  // Fetch all devices

        res.render('devicesList', { devices, admin });  // Render the devices list page
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

router.get('/devices/new', authenticateToken, (req, res) => {
    res.render('devices/new');
});

router.post('/devices', authenticateToken, async (req, res) => {
    const { deviceName, description, capacity, material, purchasePrice, powerConsumption, costPerHour, monthlyCost, applianceCategory } = req.body;

    try {
        const newDevice = new Device({
            deviceName,
            description,
            capacity,
            material,
            purchasePrice,
            powerConsumption,
            costPerHour,
            monthlyCost,
            applianceCategory
        });

        await newDevice.save();
        res.redirect('/devices');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

router.get('/device/:id', authenticateToken, async (req, res) => {
    try {
        const device = await Device.findById(req.params.id);
        if (!device) {
            return res.status(404).send('Device not found');
        }
        res.json(device);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

router.put('/devices/edit/:id', authenticateToken, async (req, res) => {
    const { deviceName, description, capacity, material, purchasePrice, powerConsumption, costPerHour, monthlyCost, applianceCategory } = req.body;

    try {
        const updatedDevice = await Device.findByIdAndUpdate(req.params.id, {
            deviceName,
            description,
            capacity,
            material,
            purchasePrice,
            powerConsumption,
            costPerHour,
            monthlyCost,
            applianceCategory
        }, { new: true });

        if (!updatedDevice) {
            return res.status(404).send('Device not found');
        }

        res.json(updatedDevice);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

router.delete('/devices/delete/:id', authenticateToken, async (req, res) => {
    try {
        const deletedDevice = await Device.findByIdAndDelete(req.params.id);
        if (!deletedDevice) {
            return res.status(404).send('Device not found');
        }
        res.json({ message: 'Device deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});


router.get('/providers', authenticateToken, async (req, res) => {
    try {
        const admin = await User.findById(req.user.userId).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        const providers = await EnergyProvider.find();

        res.render('energyProvider', { providers, admin });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});


router.post('/providers', async (req, res) => {
    try {
        const { providerName, ratePerKwh } = req.body;

        const newProvider = new EnergyProvider({ providerName, ratePerKwh });
        await newProvider.save();

        res.status(201).json({ message: 'Energy provider added successfully', newProvider });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add energy provider', details: error.message });
    }
});

router.put('/providers/edit/:id', authenticateToken, async (req, res) => {
    try {
        const { providerName, ratePerKwh } = req.body;

        const updatedProvider = await EnergyProvider.findByIdAndUpdate(
            req.params.id,
            { providerName, ratePerKwh },
            { new: true }
        );

        if (!updatedProvider) {
            return res.status(404).send('Provider not found');
        }

        res.json(updatedProvider);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

router.delete('/providers/delete/:id', authenticateToken, async (req, res) => {
    try {
        const deletedProvider = await EnergyProvider.findByIdAndDelete(req.params.id);

        if (!deletedProvider) {
            return res.status(404).send('Provider not found');
        }

        res.status(204).send(); // No content, deletion successful
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

router.get('/providers/:id', authenticateToken, async (req, res) => {
    try {
        const provider = await EnergyProvider.findById(req.params.id);

        if (!provider) {
            return res.status(404).send('Provider not found');
        }

        res.json(provider);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});


router.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

module.exports = router;