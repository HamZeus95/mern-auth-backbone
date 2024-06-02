const express = require("express");
const router = express.Router(); 
const verifyJWT = require('../middleware/verifyJWT');
const loginLimiter = require('../middleware/loginLimiter');
const UserController = require("../controllers/UserController");


router.route('/login').post(loginLimiter, UserController.login);
router.route('/refresh').get(UserController.refreshToken);
router.route('/logout').post(UserController.logout);

router.route('/')
      .get(verifyJWT,UserController.getAllUsers)
      .delete(verifyJWT,UserController.deleteUser)
      .patch(verifyJWT,UserController.updateUser)
      .post(verifyJWT,UserController.register); 















module.exports=router;