const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Auth routes
router.post('/auth/signup', authController.signup);
router.post('/auth/login', authController.login);
router.get('/auth/profile', authController.profile);
router.get('/auth/users', authController.getUsers);

module.exports = router;

