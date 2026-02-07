const express = require('express');
const router = express.Router();
const Project = require('../models/Project');
const auth = require('../middleware/auth');
const adminAuth = require('../middleware/adminAuth');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'kamp_secret_key_2026';

// Helper to get user from token if exists (without throwing error)
const getOptionalUser = async (req) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded;
  } catch (err) {
    return null;
  }
};

// @route   GET /api/projects
// @desc    Get all projects (filtered by approval status)
router.get('/', async (req, res) => {
  try {
    const decoded = await getOptionalUser(req);
    let query = {};

    if (decoded) {
      // Check if user is Admin
      const User = require('../models/User');
      const user = await User.findById(decoded.id);
      
      if (user && user.type === 'Admin') {
        // Admin sees everything
        query = {};
      } else {
        // Logged in user sees approved projects (or legacy ones) OR their own pending/rejected projects
        query = {
          $or: [
            { approvalStatus: 'approved' },
            { approvalStatus: { $exists: false } }, // Handle existing projects
            { creatorId: decoded.id }
          ]
        };
      }
    } else {
      // Non-logged in users only see approved projects (or legacy ones)
      query = { 
        $or: [
          { approvalStatus: 'approved' },
          { approvalStatus: { $exists: false } }
        ]
      };
    }

    const projects = await Project.find(query)
      .sort({ createdAt: -1 })
      .populate('creatorId', 'name email');
    res.json(projects);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// @route   POST /api/projects
// @desc    Create a new project
router.post('/', auth, async (req, res) => {
  const projectData = {
    ...req.body,
    creatorId: req.userId,
    approvalStatus: req.user.type === 'Admin' ? 'approved' : 'pending' // Admin projects are auto-approved
  };
  
  const project = new Project(projectData);
  try {
    const newProject = await project.save();
    res.status(201).json(newProject);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// @route   PUT /api/projects/:id/approve
// @desc    Approve a project (Admin only)
router.put('/:id/approve', adminAuth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    
    project.approvalStatus = 'approved';
    await project.save();
    res.json(project);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// @route   PUT /api/projects/:id/reject
// @desc    Reject a project (Admin only)
router.put('/:id/reject', adminAuth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    
    project.approvalStatus = 'rejected';
    await project.save();
    res.json(project);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// @route   GET /api/projects/:id
// @desc    Get project by ID
router.get('/:id', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    
    // Visibility check
    const decoded = await getOptionalUser(req);
    const User = require('../models/User');
    const user = decoded ? await User.findById(decoded.id) : null;
    const isAdmin = user && user.type === 'Admin';
    const isCreator = decoded && project.creatorId && project.creatorId.toString() === decoded.id;

    if (project.approvalStatus !== 'approved' && !isAdmin && !isCreator) {
      return res.status(403).json({ message: 'Project not approved yet' });
    }
    
    res.json(project);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
