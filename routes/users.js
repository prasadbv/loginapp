var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = require('../models/user');

router.get('/login',function(req,res){
	res.render('login');
});

router.get('/register',function(req,res){
	res.render('register');
});

router.post('/register',function(req,res,next){
	req.check('name','Please Enter the Name').notEmpty().isAlphanumeric().isLength({min:4});
	req.check('email', 'Email required').notEmpty();
	req.check('email','Email not valid').isEmail();
	req.check('password','password required').notEmpty();
	req.check('cpassword','Confirm password required').notEmpty();
	req.check('cpassword','Passwords do not match').equals(req.body.password);
	req.check('role_id','User Role required').notEmpty();
	var errors = req.validationErrors(true);
	if(errors){
		res.render('register',{errors:errors});
	}else{
		var newUser = new User({
			name: req.body.name,
			email: req.body.email,
			password: req.body.password,
			role_id: req.body.role_id
		});
		User.createUser(newUser,function(err,user){
			if(err) {
				req.flash('error_msg', err);
				res.redirect('/users/register');
			}else{				
				req.flash('success_msg', "You are registered and now login");
				res.redirect('/users/login');
			}	
		});		
	}
});


passport.use(new LocalStrategy(
	{
    usernameField: 'email',
    passwordField: 'password',
    session: false
  },
  function(username, password, done) {
  	User.getUserByEmail(username,function(err,user){ 
  		if(err) throw err;  		
  		if(!user){
  			return done(null,false,{message:'Unknown Email'});
  		}

  		User.comparePassword(password,user.password,function(err,isMatch){
  			if(err) throw err;
  			if(isMatch){
  				return done(null,user);
  			}else{
  				return done(null,false, {message:'Invalid Password'});
  			}
  		});
  	});    
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});



router.post('/login',passport.authenticate('local',{successRedirect:'/',failureRedirect:'/users/login',failureFlash:true}),
  function(req, res) {   	
    res.redirect('/');
  });


router.get('/logout',function(req,res,next){
	req.logout();
	req.flash('success_msg' ,'You are logged out.');
	res.redirect('/users/login');
});
module.exports = router;