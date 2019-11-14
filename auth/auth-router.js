const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken') //1

const Users = require('../users/users-model');
const { validateUser } = require('../users/users-helper')

router.post('/register', (req, res) => {
    let user = req.body;
    //always validate data before sending to DB
    const validateResult = validateUser(user);
  
    if(validateResult.isSuccessful === true){
      const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
      user.password = hash;
  
      Users.add(user)
        .then(saved => {
          res.status(201).json(saved);
        })
        .catch(error => {
          res.status(500).json(error);
        });
    }else{
      res.status(400).json({ message: "Invalid information about the user" })
    }
});

router.post('/login', (req, res) => {
    let { username, password } = req.body;
  
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          //2 produce a token
          const token = getJwtToken(user.username); 
          //3 send token to client
          res.status(200).json({
            message: `Welcome ${user.username}! have a token`,
            token
          });
        } else {
          res.status(401).json({ message: 'Invalid Credentials' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
});

function getJwtToken(username){
    const payload = {
      username,
      role: 'student' //this will probably come form the DB
    }
  
    const secret = process.env.JWT_SECRET || "is it secret? is it safe?";
  
    const options = {
      expiresIn: "1d"
    }
    return jwt.sign(payload, secret, options)
}
  
module.exports = router;