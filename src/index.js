// require('dotenv').config({path: './env'})
import dotenv from "dotenv"

// import mongoose from "mongoose";
// import { DB_NAME } from "./constants";
import connectDB from "./db/index.js";
import { app } from "./app.js";

dotenv.config({
    path: './.env'
})

connectDB()
.then(() => {
    app.listen(process.env.PORT || 8000, () => {
        console.log(`✅ Server is running on http://localhost:${process.env.PORT || 8000}`);
    })
})
.catch((err) => {
    console.log("MONGO DB connection failed!", err)
})

/*
import express from "express"
const app = express()

// ifiies
;( async () => {
    try {
        await mongoose.connect(`${process.env.MONOGODB_URI}/${DB_NAME}`)
        app.on("error", (error) => {
            console.log("ERR: ", error);
            throw error
        })

        app.listen(process.env.PORT, () => {
            console.log(`App is listening on port ${process.env.PORT}.`)
        })

    } catch (error){
        console.error("ERROR: ", error)
        throw err
    }
})()

*/