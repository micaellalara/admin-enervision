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

router.get('/api/average-appliances', async (req, res) => {
    const { start, end } = req.query;

    if (!start || !end) {
        return res.status(400).json({ error: "Start and end dates are required." });
    }

    try {
        // Calculate average appliances per day within the specified date range
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

        // Get today's date range
        const today = new Date();
        const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        const endOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);

        // Calculate appliances added today
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

        // Calculate total appliances stored for all users
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
            totalAppliancesStored: totalAppliances // Include total appliances stored for all users
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
                applianceCount: user.appliances.length // Count of appliances for each user
            };
        });

        const today = new Date();
        const startOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        const endOfToday = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);

        const usersRegisteredToday = await User.countDocuments({ createdAt: { $gte: startOfToday, $lt: endOfToday } });
        const totalUsers = await User.countDocuments();
        const postsAddedToday = await Post.countDocuments({ createdAt: { $gte: startOfToday, $lt: endOfToday } });

        // Get total appliances for all users (not just today's)
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
            totalAppliances, // This is now the total number of appliances for all users
            appliancesAddedToday: appliancesAddedTodayCount, // This is only today's appliances
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

        post.flagged = true; // You can also add other properties or logic as needed
        await post.save();
        
        res.redirect('/userposts'); // Redirect back to userposts
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
        res.redirect('/userposts'); // Redirect back to userposts
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

        // Combine user, username, and profile details
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

        // Calculate start and end indices for the displayed users
        const startIndex = (currentPage - 1) * usersPerPage + 1; // Start from 1
        const endIndex = Math.min(startIndex + users.length - 1, totalCount); // Ensure it does not exceed total count

        // Render the userProfiles EJS file with the fetched data
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
        const user = await User.findById(req.params.id).populate('appliances'); // Populate the appliances field

        const profile = await UserProfile.findOne({ userId: user._id });
        const userPosts = await Post.aggregate([
            { $match: { userId: user._id } },
            { $group: { _id: "$userId", postCount: { $sum: 1 } } }
        ]);

        // Count the number of appliances
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
            banDate: profile ? profile.banDate : null, // Correctly fetch banDate from profile
            postCount: userPosts.length > 0 ? userPosts[0].postCount : 0,
            applianceCount // Send the appliance count
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Route to edit a user's profile
router.get('/profile/edit/:id', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        const profile = await UserProfile.findOne({ userId: user._id });

        if (!user || !profile) {
            return res.status(404).send('User not found');
        }

        res.render('editProfile', { user, profile }); // Render edit profile page
    } catch (error) {
        console.error('Error fetching user for edit:', error);
        res.status(500).send('Server error');
    }
});

// Route to deactivate a user's profile
router.post('/profile/deactivate/:id', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.params.id, { status: 'deactivated' }); // Update user status
        res.redirect('/user-profiles'); // Redirect back to user profiles
    } catch (error) {
        console.error('Error deactivating user:', error);
        res.status(500).send('Server error');
    }
});

// Route to delete a user's profile
router.post('/profile/delete/:id', authenticateToken, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id); // Delete user by ID
        res.redirect('/user-profiles'); // Redirect back to user profiles
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).send('Server error');
    }
});

router.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

module.exports = router;