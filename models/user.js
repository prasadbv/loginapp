var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');

var UserSchema = mongoose.Schema({
	name:{
		type: String
	},
	email:{
		type:String,
		index:true
	},
	password:{
		type: String
	},
	role_id:{
		type: Number,
		integer: true
	}
});

var User = module.exports = mongoose.model('User',UserSchema);

module.exports.createUser = function(newUser,callback){
	User.find({email:newUser.email},function(err,docs){ 
		if(docs.length>0){
			callback("User Already exist!",null);
		}else{
			bcrypt.genSalt(10, function(err, salt) {
		    bcrypt.hash(newUser.password, salt, function(err, hash) {
		        newUser.password = hash;
		        newUser.save(callback);
		    });
			});
		}
	})	
}

module.exports.getUserByEmail = function(email,callback){	
	var query = {email:email};
	User.findOne(query,callback);
}

module.exports.comparePassword = function(inputPassword,hash,callback){
	bcrypt.compare(inputPassword,hash,function(err,isMatch){
		if(err) throw err;
		callback(null,isMatch);
	});
}

module.exports.getUserById = function(id,callback){
	User.findById(id,callback);
}