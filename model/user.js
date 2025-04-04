const mongoose=require('mongoose');

const userschema=  mongoose.Schema({
      username:String,
      name:String,
      age:Number,
      email:String,
      password:String,
      role: {
        type: String,
        enum: ['ADMIN', 'CITIZEN', 'OFFICER'],
        default: 'CITIZEN'
      },
      posts:[{type:mongoose.Schema.Types.ObjectId,ref:"post"}],
      comments:[{type:mongoose.Schema.Types.ObjectId,ref:"comment"}]
})

module.exports=mongoose.model("user",userschema);