const jwt = require('jsonwebtoken');
const redis = require('redis');
const redisClient = redis.createClient(process.env.REDIS_URI);


//check if the email and password are correct.
const handleSignin = (db, bcrypt, req, res) => 
{
  const { email, password } = req.body;
  
  if (!email || !password) 
  {
    return Promise.reject('incorrect form submission')
  }
    
    return db.select('email', 'hash').from('login')
      .where('email', '=', email)
        .then(data => {
            const isValid = bcrypt.compareSync(password, data[0].hash);
            if (isValid) 
              {
              return db.select('*').from('users')
              .where('email', '=', email)
              .then(user => user[0])
              .catch(err => Promise.reject('unable to get user'))
              } 
              else      
              {
               return Promise.reject('wrong credentials')
              }})
                .catch(err => Promise.reject('wrong credentials'))
}


const getAuthTokenId = (req, res) => {
  const { authorization } =req.headers;
  return redisClient.get(authorization, (err, reply) => {
    if (err || !reply) {
      return res.status(400).json('UNAUTHORIZED')
    }

    return res.json({ id: reply })
  })
}

const signToken = (email) => {
  const jwtPayload = { email };
  return jwt.sign(jwtPayload, 'secret');
}


const setToken = (token, id) => {
  return Promise.resolve(redisClient.set(token, id))
}

const createSessions = (user) => {
  //CREATE TOKEN AND RETURN THE DATA
    const { email, id } = user;
    const token = signToken(email);
    return setToken(token, id)
            .then(() => {
              return {success: 'true', userId: id, token: token};
            })
            .catch(err => console.log);
}




const signinAuthentication = (db, bcrypt) => (req, res) => {
  const { authorization } = req.headers;

  if (authorization) {
    return getAuthTokenId(req, res);
  } 


  else if (!authorization){
    return handleSignin(db, bcrypt, req, res)
            .then(data => {
             const {id, email} = data;
              if (id && email) {
              return createSessions(data)
              }
              else {
               return Promise.reject(data);
              }
              
            })
            .then(session => {
              res.json(session)
            })
            .catch(err => res.status(400).json('Error in signin.js line 45.'))
  }


}

module.exports = {
  signinAuthentication: signinAuthentication,
  redisClient: redisClient
}