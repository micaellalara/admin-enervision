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
const FAQ = require('../model/faqs.model');

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
        const admin = await Admin.findById(req.admin.id).select('-password');
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
        });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Server error');
    }
});



router.get('/userposts', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.admin.id).select('-password');
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
        const admin = await Admin.findById(req.admin.id);

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

        const admin = req.admin;

        res.render('deletedPosts', { deletedPosts, admin });
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

        // Send a success response
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
        const currentPage = parseInt(req.query.page) || 1;
        const usersPerPage = 5;

        // Find users and their associated profiles
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

router.post('/deleteUser/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Delete user
        await User.findByIdAndDelete(userId);

        res.redirect('/userProfiles');
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).send('Server error');
    }
});

router.post('/deactivateUser/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.params.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        user.status = 'inactive';
        await user.save();

        res.redirect('/userProfiles');
    } catch (error) {
        console.error('Error deactivating user:', error);
        res.status(500).send('Server error');
    }
});

router.get('/faqs', authenticateToken, async (req, res) => {
    try {
        const faqs = await FAQ.find();

        const admin = await Admin.findById(req.admin.id);
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

        const admin = await Admin.findById(req.admin.id);
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



// router.post('/profile/deactivate/:id', authenticateToken, async (req, res) => {
//     try {
//         await User.findByIdAndUpdate(req.params.id, { status: 'deactivated' });
//         const profile = await UserProfile.findOne({ userId: user._id });

//         res.redirect('/user-profiles'); 
//     } catch (error) {
//         console.error('Error deactivating user:', error);
//         res.status(500).send('Server error');
//     }
// });

// router.post('/profile/delete/:id', authenticateToken, async (req, res) => {
//     try {
//         await User.findByIdAndDelete(req.params.id); 
//         const profile = await UserProfile.findOne({ userId: user._id });

//         res.redirect('/user-profiles');
//     } catch (error) {
//         console.error('Error deleting user:', error);
//         res.status(500).send('Server error');
//     }
// });

router.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

module.exports = router;