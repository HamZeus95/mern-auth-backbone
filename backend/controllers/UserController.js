const User = require("../models/User");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


class UserController {

    async register(req, res) {
        try {
            const {  email, password, roles, firstName, lastName } = req.body;

            // confirm data is present
            if (!email || !password || !roles || !firstName || !lastName) {
                return res.status(400).json({ message: 'All fields are required' });
            };
            // confirm user does not already exist 
            const existingUser = await User.findOne({email})
            .collation({ locale: 'en', strength: 2 })
            .lean()
            .exec();
            if (existingUser) {
                return res.status(400).json({ message: 'User already exists' });
            };
            // hash password
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = new User({ email, password: hashedPassword, roles, firstName, lastName });
            const savedUser = await newUser.save();
            res.status(201).json({ message: `New user ${savedUser?.firstName} created` });
        } catch (err) {
            res.status(500).json(err);
        }
    }

     
    async login (req, res) {
        try{
            const { email, password } = req.body

    if (!email || !password) {
        return res.status(400).json({ message: 'All fields are required' })
    }

    const foundUser = await User.findOne({ email }).exec()

    if (!foundUser || !foundUser.active) {
        return res.status(401).json({ message: 'Unauthorized' })
    }

    const match = await bcrypt.compare(password, foundUser.password)

    if (!match) return res.status(401).json({ message: 'Unauthorized' })

    const accessToken = jwt.sign(
        {
            "UserInfo": {
                "email": foundUser.email,
                "roles": foundUser.roles
            }
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
    )

    const refreshToken = jwt.sign(
        { "email": foundUser.email },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    )

    // Create secure cookie with refresh token 
    res.cookie('jwt', refreshToken, {
        httpOnly: true, //accessible only by web server 
        secure: true, //https
        sameSite: 'None', //cross-site cookie 
        maxAge: 7 * 24 * 60 * 60 * 1000 //cookie expiry: set to match rT
    })

    // Send accessToken containing email and roles 
    res.json({ accessToken })
        }catch(err){
            res.status(500).json(err)
        }
    }

    async refreshToken(req, res) {
        try {
            const cookies = req.cookies

            if (!cookies?.jwt) return res.status(401).json({ message: 'Unauthorized' })
        
            const refreshToken = cookies.jwt
        
            jwt.verify(
                refreshToken,
                process.env.REFRESH_TOKEN_SECRET,
                async (err, decoded) => {
                    if (err) return res.status(403).json({ message: 'Forbidden' })
        
                    const foundUser = await User.findOne({ email: decoded.email }).exec()
        
                    if (!foundUser) return res.status(401).json({ message: 'Unauthorized' })
        
                    const accessToken = jwt.sign(
                        {
                            "UserInfo": {
                                "email": foundUser.email,
                                "roles": foundUser.roles
                            }
                        },
                        process.env.ACCESS_TOKEN_SECRET,
                        { expiresIn: '15m' }
                    )
        
                    res.json({ accessToken })
                }
            )
        } catch (err) {
            res.status(500).json(err)
        }
    }
    async logout(req, res) {
        try {
            const cookies = req.cookies
            if (!cookies?.jwt) return res.sendStatus(204) //No content
            res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
            res.json({ message: 'Cookie cleared' })
        }catch(err){
            res.status(500).json(err)
        }
    }

    async getAllUsers(req, res) {
        try {
            const users = await User.find().select('-password').lean();
            res.json(users)
        } catch (err) {
            res.status(500).json(err)
        }
    }

    async getUser(req, res) {
        try {
            const user = await User.findById(req.params.id).select('-password').lean();
            res.json(user)
        } catch (err) {
            res.status(500).json(err)
        }
    }
    async updateUser(req, res) {
        try {
            const { email, roles, firstName, lastName, active } = req.body;
            const { id } = req.params;

            if (!email || !Array.isArray(roles) || !roles.length || typeof active !== 'boolean') {
                return res.status(400).json({ message: 'All fields except password are required' })
            }
            // Does the user exist to update?
            const user = await User.findById(id).exec()

            if (!user) {
                return res.status(400).json({ message: 'User not found' })
            }
                    // Check for duplicate 
            const duplicate = await User.findOne({ email }).collation({ locale: 'en', strength: 2 }).lean().exec()

            // Allow updates to the original user 
            if (duplicate && duplicate?._id.toString() !== id) {
                return res.status(409).json({ message: 'Duplicate email' })
            }

            user.email = email
            user.roles = roles
            user.firstName = firstName
            user.lastName = lastName
            user.active = active
        
            if (password) {
                // Hash password 
                user.password = await bcrypt.hash(password, 10); // salt rounds 
            }
        
            const updatedUser = await user.save();

            res.json({ message: `User ${updatedUser.firstName} updated` })
        }catch(err){
            res.status(500).json(err)
        }
    }

    async deleteUser(req, res) {
        try {
            const { id } = req.params; 

            // Confirm data
            if (!id) {
                return res.status(400).json({ message: 'User ID Required' })
            }
          
            // Does the user exist to delete?
            const user = await User.findById(id).exec()
        
            if (!user) {
                return res.status(400).json({ message: 'User not found' })
            }
        
            const result = await user.deleteOne()
        
            const reply = `user ${result.firstName} with ID ${result._id} deleted`
        
            res.json(reply)
        }catch(err){
            res.status(500).json(err)
        }
    }
};

module.exports = new UserController();