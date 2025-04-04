const mongoose=require('mongoose');
mongoose.connect('mongodb://localhost:27017/Data-Association');
const userschema=  mongoose.Schema({
      username:String,
      name:String,
      age:Number,
      email:String,
      password:String,
      posts:[{type:mongoose.Schema.Types.ObjectId,ref:"post"}],
      comments:[{type:mongoose.Schema.Types.ObjectId,ref:"comment"}]
})


module.exports=mongoose.model("user",userschema);