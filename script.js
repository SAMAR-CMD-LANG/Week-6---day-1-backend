import express from 'express';
import dotenv from "dotenv";
import { supabase } from './db.js';
dotenv.config();
import jwt from 'jsonwebtoken';
import cors from 'cors';
import bcrypt from "bcrypt";
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey29829484932849";


async function authenticateToken(req,res,next){
    const authHeader = req.headers['authorization'] || "";
    const token = authHeader && authHeader.split(" ")[1];
    if(!token){
        return res.status(401).json({message:"No token provided"});
    }
    try{
        const decoded=jwt.verify(token,JWT_SECRET);
        req.user=decoded;
        next();
    }
    catch(err){
        return res.status(401).json({message:"Invalid token"});
    }
}

app.post("/auth/register",async(req,res)=>{
    const{name,email,password}=req.body;
 if(!name || !email || !password){
    return res.status(400).json({message:"Name , email and password are required"});
 };
 const{data:existingUser,error}=await supabase
 .from("Users")
 .select("*")
 .eq("email",email)
 .single();

 if(existingUser){
    return res.status(400).json({message:"User already exists"});
 }
 const hashedPassword=await bcrypt.hash(password,10);
 const{data:newUser,error:createError}=await supabase
 .from("Users")
 .insert([{name,email,password:hashedPassword}])
 .select()
 .single();
 if(createError){
    return res.status(500).json({message:"Error creating user"});
 }
 res.status(201).json({message:"User registered successfully"},{user:newUser});
});

app.post("/auth/login",async(req,res)=>{
    const{email,password}=req.body;
    if(!email || !password){
        return res.status(400).json({message:"email and password both are needed"});

    }
    try{
            const{data:user,error}=await supabase
    .from("Users")
    .select("*")
    .eq("email",email)
    .single();
    if(!user || error){
        return res.status(400).json({message:"user does not exist"});
    }
    const isMatch=await bcrypt.compare(password,user.password);
    if(!isMatch){
        return res.status(400).json({message:"Invalid password"});
    }
    const token = jwt.sign({id:user.id,email:user.email},JWT_SECRET,{expiresIn:"1h"});
    res.json({message:"Login successful",token});
    }
    catch(err){
     res.status(500).json({message:"server error"});
    }

});


app.get("/posts",async(req,res)=>{
    try{
        const{data:posts,error}=await supabase
        .from("Posts")
        .select("*")
        .order("created_at",{ascending:false});

        if(error || !posts){
            return res.status(500).json({message:"Error fetching posts from DB"})
        };
        res.json({posts})
    }
    catch(err){
        res.status(500).json({message:"Posts fetch failed from server!"});
    }
});

app.post("/posts",authenticateToken,async(req,res)=>{
    const{title,body}=req.body;
    const user_id=req.user.id;
    if(!title || !body){
        return res.status(400).json({message:"Title and body are required"});
    }
    try{
        const{data:post,error}=await supabase
        .from("Posts")
        .insert([{title,body,user_id}])
        .select()
        .single();
        if(error){
            return res.status(400).json({message:"Error creating post"});
        }
        res.status(201).json({message:"post created successfully",post});
    }
    catch(err){
        res.status(500).json({message:"Server error while creating post"});
    }
});
app.put("/posts/:id",authenticateToken,async(req,res)=>{
    const postId=req.params.id;
    const{title,body}=req.body;
    const user_id=req.user.id;
    try{
        const{data:updatedPost,error}=await supabase
        .from("Posts")
        .update({title,body})
        .eq("id",postId)
        .eq("user_id",user_id)
        .select()
        .single();
        if(error){
            return res.status(403).json({error:"Not authorized to update this post"});
        }
        res.status(200).json(updated);

    }
    catch(err){
        console.error(err);
        res.status(500).json({error:"Server error while updating post"});
    }
});

app.delete("/posts/:id",authenticateToken,async(req,res)=>{
    const postId=req.params.id;
    const user_id=req.user.id;  
    try{
        const{data, error}=await supabase
        .from("Posts")
        .delete()
        .eq("id",postId)
        .eq("user_id",user_id)
        .select()
        .single();
        if(error){
            return res.status(403).json({message:"Not authorized to delete this post"});
        }       
        res.status(200).json({message:"Post deleted successfully",post:data});
    }
    catch(err){
        console.error(err);
        res.status(500).json({message:"Server error while deleting post"});
    }   
});


app.listen(PORT,()=>{
    console.log(`Server is running on port ${PORT}`);
});

