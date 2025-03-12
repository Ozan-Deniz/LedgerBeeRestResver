//Core libraries
const https = require('https');
const fs = require('fs');
const express = require('express');
const {Pool} = require('pg');

//middleware and utilities
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require("google-auth-library");

//Security and encryption
const bcrypt = require('bcrypt');
const saltRounds = 12; // The cost factor determines the complexity of the hashing process
const jwt = require('jsonwebtoken');
const { verify } = require('crypto');

//Environment variables
require('dotenv').config();
const PORT = 3000;

const google_client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);




const app = express();
app.use(cors({credentials:true, origin: process.env.CORS_ORIGIN,}));
app.use(express.json());
app.use(cookieParser());


const email_regex = new RegExp("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
const password_regex = /^[^\s]{8,64}$/;
const date_regex = /^\d{4}-\d{2}-\d{2}$/;

const guestRegisterLimiter = rateLimit( {
    windowMs : 10000,// 10.000 ms = 10 seconds
    max:1,
    message:"Too many guest register requests. Please try again later."
}); 

const options = {
    key: fs.readFileSync(process.env.SSL_KEY_PATH),
    cert: fs.readFileSync(process.env.SSL_CERT_PATH)
};

const db = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT, // default port for PostgreSQL
});

db.connect().then(()=>{
    console.log("Connected to the database.");
}).catch(err=>{
    console.error("Database connection error: ", err.stack);
});




app.get('/', (req, res) => {
    res.json(getMessage("Server is running!"));
});


//Validation methods
const checkNumberError = (...nums) => {
    for (const num of nums) {
        if (typeof num !== 'number' || isNaN(num)) {
            return true;
        }
    }
    return false;
};




const loginHandler = async (req, res)=>{
    
    let {username, password} = req.body;

    if (!username || !password) {

        return res.json(getMessage("missingCred")); // Missing credentials
    }
    username=username.toLowerCase();

    const result = await db.query('SELECT id, token_version, password FROM auth WHERE username = $1' ,
        [username]
    );
    if(result.rowCount===0){
        return res.json(getMessage("WrongCred"));//wrong credentials
    }

    let row = result.rows[0];
    
    const passMatched = await bcrypt.compare(password, row.password);

    if(!passMatched)return res.json(getMessage("WrongCred"));

    let r = getMessage("loginSucc");

    let token_version = Number(row.token_version);
    let refresh_token = generateRefreshToken(row.id, token_version);

    addRefreshCookie(res,refresh_token);

    r.username = username;
    return res.json(r);
};

const logoutHandler = async (req, res, access_payload)=>{
    removeAccessToken(res);
    const refresh_token = req.cookies.refresh_token;
    removeRefreshToken(res);
    if(!req.cookies.refresh_token){
        return res.json(getMessage("logoutFail")); 
    }

    const secret = process.env.JWT_REFRESH_SECRET;
    const payload = jwt.verify(refresh_token, secret);

    
    if (payload.userid == null || payload.version == null) {
        return res.json(getMessage("logoutFail"));
    }

    db.query('UPDATE auth SET token_version = token_version + 1 WHERE id = $1 AND token_version = $2' ,
        [payload.userid, payload.version]
    );


    return res.json(getMessage("logoutSucc"));
};

const registerHandler = async (req,res)=>{

    let {username, password} = req.body;
    if(!username)throw new Error("Username cannot be empty.");
    if(!password)throw new Error("Password cannot be empty.");

    if(!email_regex.test(username)){throw new Error("Invalid email.");}
    if(!password_regex.test(password)){throw new Error("Invalid password.");}

    username=username.toLowerCase();
    password = await hash_pass(password);
    
    const result = await db.query('SELECT * FROM auth WHERE username = $1',[username]);
    
    
    if(result.rowCount!==0){
        return res.json(getMessage("UserExists"));
    }
   
    await db.query('INSERT INTO auth (username, password) VALUES ($1, $2)',[username,password]);
    return res.json(getMessage("RegisterSucc"));
}
const generateRefreshToken = (userid, version) => {
    console.log("Generate refresh token, userid is "+userid+" version is "+version);
    const payload = {
        userid,
        version
    };

    const secret = process.env.JWT_REFRESH_SECRET;
    const options={
        expiresIn: process.env.JWT_REFRESH_EXPIRES || "99y",
    };


    return jwt.sign(payload,secret, options);
}

const generateAccessToken = (userid) => {
    const payload = {
        userid
    };

    const secret = process.env.JWT_ACCESS_SECRET;
    const options={
        expiresIn: process.env.JWT_ACCESS_EXPIRES || "15m",
    };

    return jwt.sign(payload,secret, options);

}

const verifyGoogleIdToken = async (token) => {
  const ticket = await google_client.verifyIdToken({
    idToken: token,
    audience: process.env.GOOGLE_CLIENT_ID,  // Ensure it's issued for your app
  });

  const payload = ticket.getPayload();  // Extract user info

  return payload;
}


const refreshAccessTokenHandler = async (req, res)=>{
    
    let refresh_token = req.cookies.refresh_token;
    if(!refresh_token){return res.json(getMessage("refreshAccessFail"));}

    const secret = process.env.JWT_REFRESH_SECRET;
    try{
        const payload = jwt.verify(refresh_token, secret);

        if (payload.userid == null || payload.version == null){

            removeRefreshToken(res);
            return res.json(getMessage("refreshAccessFail"));
        }
        
        const result = await db.query('SELECT username, token_version FROM auth WHERE id = $1',[payload.userid]);
        
        if(result.rowCount===0){

            removeRefreshToken(res);
            return res.json(getMessage("refreshAccessFail"));
        }

        let row = result.rows[0];

        if(payload.version !== row.token_version){
            removeRefreshToken(res);
            return res.json(getMessage("refreshAccessFail"));
        }
        let access_token = generateAccessToken(payload.userid);

        addAccessToken(res,access_token);
        
        let r = getMessage("refreshAccessSucc");
        r.username = row.username;
        return res.json(r);

    }
    catch(err){
        removeRefreshToken(res);
        return res.json(getMessage("autoLoginFail"));
    }
    
        
};

const isProduction = () => process.env.NODE_ENV === 'production';


const guestRegisterHandler = async (req,res)=>{
    guestRegisterLimiter(req, res, async  () => {

        const result = await db.query('INSERT INTO auth DEFAULT VALUES RETURNING id, token_version');

        const { id, token_version } = result.rows[0];

        const refresh_token = generateRefreshToken(id,token_version);

        addRefreshCookie(res,refresh_token);
        

        return res.json(getMessage("guestRegisterSucc"));
    });
}

const hash_pass = async (pass)=>{

    try{
        return await bcrypt.hash(pass, saltRounds);
    }
    catch(error){
        throw new Error("Error while hashing the password.");
    }
}

const getMessage = (message_type)=>{
    return {type:message_type};
}

const getError = (error_info) =>{
    return {type:"error", info:error_info};
}

const getPopupError = (error_info) =>{//implement this in a way on client side to automatically show the info on popup. For example, show it on PrimeVue's Toast componet.
    return {type:"popup_error", info:error_info};
}

const addRefreshCookie = (res, token) => {
    res.cookie('refresh_token', token, {
        httpOnly: true, // Cannot be accessed by JavaScript (prevents XSS)
        secure: true, // Only send over HTTPS in production
        maxAge: 3650 * 1000 * 60 * 60 * 24, // Expires in 10 years (also expires on logout)
        sameSite: isProduction() ? 'Strict' : 'None', // Helps prevent CSRF attacks
    });
}

const addAccessToken = (res, token) => {
    res.cookie('access_token', token, {
        httpOnly: true, // Cannot be accessed by JavaScript (prevents XSS)
        secure: true, // Only send over HTTPS in production
        maxAge: 1000 * 60 * 15, // Expires in 15 minutes (also expires on logout)
        sameSite: isProduction() ? 'Strict' : 'None', // Helps prevent CSRF attacks
    });
}
const removeRefreshToken = (res) => {
    res.clearCookie('refresh_token', {
        httpOnly: true,
        secure: true,
        sameSite: isProduction() ? 'Strict' : 'None',
    });
}

const removeAccessToken = (res) => {
    res.clearCookie('access_token', {
        httpOnly: true,
        secure: true,
        sameSite: isProduction() ? 'Strict' : 'None',
    });
}

const addStoreHandler = async (req, res, payload) => {
 
    let {name} = req.body;
    if(!name || name.length > 64)return res.json(getMessage("error"));
    
    const result = await db.query('INSERT INTO stores (user_id, name) VALUES ($1, $2) RETURNING store_id',
        [payload.userid, name]
    );

    if(result.rowCount==0) return res.json(getMessage("error"));

    const store_id = result.rows[0].store_id;
    let msg = getMessage("success");
    msg.store = {name, store_id};
    return res.json(msg);
}

const getStoresHandler = async (req, res, payload) => {
     
    const result = await db.query('SELECT name, store_id, is_visible FROM stores WHERE user_id = $1',
        [payload.userid]
    );

    let msg = getMessage("success");
    msg.stores = result.rows;
    return res.json(msg);
}

const getStoreDataHandler = async (req, res, payload) => {

    let {store_id} = req.body;
    if(store_id==null){return res.json(getPopupError("Something went wrong."));}
    if(checkNumberError(store_id))return res.json(getPopupError("Server received inappropriate data."));

    
    const result = await db.query('SELECT * FROM items WHERE user_id = $1 AND store_id = $2',
        [payload.userid, store_id]
    );

    let msg = getMessage("success");
    msg.items = result.rows;

    return res.json(msg);
}
const addItemHandler = async (req, res, payload) => {

    let {store_id, item_name, tax} = req.body;
    if(store_id == null || item_name == null ||tax == null || item_name.length>64){return res.json(getPopupError("Something went wrong."));}
    if(checkNumberError(store_id, tax))return res.json(getPopupError("Server received inappropriate data."));

    const result = await db.query('INSERT INTO items (store_id, name, default_tax, user_id) VALUES ($1, $2, $3, $4) RETURNING item_id',
        [store_id, item_name, tax, payload.userid]
    );
    if(result.rowCount===0) return res.json(getPopupError("Something went wrong."));
    

    let msg = getMessage("success");
    msg.store_id = store_id;
    msg.item_id = result.rows[0].item_id;
    msg.name = item_name;
    msg.tax = tax;

    return res.json(msg);
}
const saveReceiptHandler = async (req, res, payload) => {

    let {receipt_id, store_id, items, date} = req.body;
    if(store_id == null || items == null || receipt_id == null || date == null){return res.json(getPopupError("Something went wrong."));}
    if(!date_regex.test(date)){return res.json(getPopupError("Wrong date value."));}
    if(checkNumberError(receipt_id, store_id))return res.json(getPopupError("Server received inappropriate data."));

    if(!typeof receipt_id === "number" || !Number.isInteger(receipt_id)){return res.json(getPopupError("Something went wrong."));}

    if(receipt_id<0){
        const result = await db.query('INSERT INTO receipts (store_id, user_id, items, date) VALUES ($1, $2, $3, $4) RETURNING receipt_id',
            [store_id, payload.userid, items, date]
        );
        if(result.rowCount===0) return res.json(getPopupError("Something went wrong."));
        const msg = getMessage("addSuccess");
        msg.receipt_id = result.rows[0].receipt_id;
        msg.items = items;
        msg.store_id = store_id;
        return res.json(msg);

    }
    else{
        const result = await db.query('UPDATE receipts SET items = $3 WHERE receipt_id = $4 AND user_id = $2 AND store_id = $1',
            [store_id, payload.userid, items, receipt_id]
        );
        if(result.rowCount===0) return res.json(getPopupError("Something went wrong."));
        const msg = getMessage("updateSuccess");
        msg.receipt_id = receipt_id;
        msg.items = items;
        msg.store_id = store_id;
        return res.json(msg);
    }
}

const getReceiptDataHandler = async (req, res, payload) => {

    let {receipt_id} = req.body;
    if(receipt_id == null){return res.json(getPopupError("Something went wrong."));}
    if(checkNumberError(receipt_id))return res.json(getPopupError("Server received inappropriate data."));

    const result = await db.query('SELECT * from receipts WHERE receipt_id = $1 AND user_id = $2',
        [receipt_id, payload.userid]
    );
    if(result.rowCount===0) return res.json(getPopupError("Something went wrong."));
    const msg = getMessage("success");
    msg.items = result.rows[0].items;
    msg.receipt_id = result.rows[0].receipt_id;
    msg.store_id = result.rows[0].store_id;

    return res.json(msg);
}

const getReceiptsHandler = async (req, res, payload) => {


    let {date} = req.body;

    if(date == null){return res.json(getPopupError("Something went wrong."));}
    
    if(!date_regex.test(date)){return res.json(getPopupError("Something went wrong."));}

    const receipt_result = await db.query('SELECT store_id, receipt_id, items from receipts WHERE user_id = $1 AND date = $2 ORDER BY receipt_id ASC',
        [payload.userid, date]
    );

    const store_result = await db.query('SELECT store_id, name, is_visible from stores WHERE user_id = $1',
        [payload.userid]
    );

    const income_sources_result = await db.query('SELECT income_source_id, income_source_name, is_visible from income_sources WHERE user_id = $1',
        [payload.userid]
    );

    const incomes_result = await db.query('SELECT income_source_id, income_id, total from incomes WHERE user_id = $1 AND date = $2',
        [payload.userid, date]
    );

    const msg = getMessage("success");
    msg.receipts = receipt_result.rows;
    msg.stores = store_result.rows;
    msg.income_sources = income_sources_result.rows;
    msg.incomes = incomes_result.rows;
    return res.json(msg);
}


const addIncomeSourceHandler = async (req, res, payload) => {

    let {sourceName} = req.body;
    if(sourceName == null || sourceName.length>64){return res.json(getPopupError("Something went wrong."));}

    const result = await db.query('INSERT INTO income_sources (user_id, income_source_name) VALUES ($1, $2) RETURNING income_source_id',
        [payload.userid, sourceName]
    );

    if(result.rowCount === 0) return res.json(getPopupError("Something went wrong."));



    const msg = getMessage("success");
    msg.income_source_name = sourceName;
    msg.income_source_id = result.rows[0].income_source_id;
    return res.json(msg);
}

const setIncomeSourceVisibility = async (req, res, payload) => {

    let {income_source_id, is_visible} = req.body;
    if(income_source_id == null || is_visible == null){return res.json(getPopupError("Something went wrong."));}
    
    if(checkNumberError(income_source_id))return res.json(getPopupError("Server received inappropriate data."));
    if(typeof is_visible !== 'boolean') return res.json(getPopupError("Server received inappropriate data."));

    const result = await db.query('UPDATE income_sources SET is_visible = $1 WHERE income_source_id = $2 AND user_id = $3',
        [is_visible, income_source_id, payload.userid]
    );

    if(result.rowCount === 0) return res.json(getPopupError("Something went wrong."));

    return res.json(getMessage("success"));
}

const updateIncomeHandler = async (req, res, payload) => {
    let {income_id, income_source_id, date, total} = req.body;
    
    if(income_id == null || income_source_id == null || date == null || total == null){return res.json(getPopupError("Something went wrong."));}

    if(checkNumberError(income_id, income_source_id, total))return res.json(getPopupError("Server received inappropriate data."));

    if(income_id<0){
        const result = await db.query(`
            INSERT INTO incomes 
            (income_source_id, user_id, date, total) 
            VALUES ($1, $2, $3, $4)
            RETURNING income_id`,
            [income_source_id, payload.userid, date, total]
        );
        if(result.rowCount==0) return res.json(getPopupError("Something went wrong."));

        const msg = getMessage("success");
        msg.income_id = result.rows[0].income_id;
        return res.json(msg);
    }
    
    const result = await db.query(`
        UPDATE incomes 
        SET total = $1
        WHERE user_id = $2 AND income_id = $3`,
        [total, payload.userid, income_id]
    );
    if(result.rowCount==0) return res.json(getPopupError("Something went wrong."));
    return res.json(getMessage("success"));
}

const getStatsHandler = async (req, res, payload) => {
    let {min_date, max_date} = req.body;
    
    if(min_date == null || max_date == null){return res.json(getPopupError("Something went wrong."));}

    const receipt_result = await db.query(`
        SELECT receipt_id, store_id, items, date FROM receipts 
        WHERE user_id=$1 AND date BETWEEN $2 AND $3`,
        [payload.userid, min_date, max_date]
    );

    const stores_result = await db.query(`
        SELECT store_id, name FROM stores 
        WHERE user_id=$1`,
        [payload.userid]
    );

    const items_result = await db.query(`
        SELECT item_id, store_id, name FROM items 
        WHERE user_id=$1`,
        [payload.userid]
    );
    const incomes_result = await db.query(`
        SELECT income_id, income_source_id, date, total FROM incomes 
        WHERE user_id=$1 AND date BETWEEN $2 AND $3`,
        [payload.userid, min_date, max_date]
    );
    const income_sources_result = await db.query(`
        SELECT income_source_name, income_source_id FROM income_sources 
        WHERE user_id=$1`,
        [payload.userid]
    );
    
    const msg = getMessage("success");
    msg.receipts = receipt_result.rows;
    msg.stores = stores_result.rows;
    msg.items = items_result.rows;
    msg.incomes = incomes_result.rows;
    msg.income_sources = income_sources_result.rows;
    return res.json(msg);
}

const refreshStores = async (req, res, payload) => {

    const stores_result = await db.query(`
        SELECT store_id, name, is_visible FROM stores 
        WHERE user_id=$1 ORDER BY store_id ASC`,
        [payload.userid]
    );

    const items_result = await db.query(`
        SELECT item_id, store_id, name, is_visible, default_tax FROM items 
        WHERE user_id=$1 ORDER BY item_id ASC`,
        [payload.userid]
    );
    
    const msg = getMessage("success");
    msg.stores = stores_result.rows;
    msg.items = items_result.rows;
    return res.json(msg);
}

const setStoreVisibility = async (req, res, payload) => {
    let {is_visible, store_id} = req.body;
    
    if(is_visible == null || store_id == null){return res.json(getPopupError("Something went wrong."));}
    if(typeof is_visible !== 'boolean') return res.json(getPopupError("Server received inappropriate data."));
    if(checkNumberError(store_id))return res.json(getPopupError("Server received inappropriate data."));

    const result = await db.query(`
        UPDATE stores
        SET is_visible = $1 
        WHERE user_id=$2 AND store_id=$3`,
        [is_visible, payload.userid, store_id]
    );

    if(result.rowCount>0) return res.json(getMessage("success"));
    else return res.json(getPopupError("Something went wrong."));
}

const setItemVisibility = async (req, res, payload) => {
    let {is_visible, item_id} = req.body;
    
    if(is_visible == null || item_id == null){return res.json(getPopupError("Something went wrong."));}
    if(typeof is_visible !== 'boolean') return res.json(getPopupError("Server received inappropriate data."));
    if(checkNumberError(item_id))return res.json(getPopupError("Server received inappropriate data."));

    const result = await db.query(`
        UPDATE items
        SET is_visible = $1 
        WHERE user_id=$2 AND item_id=$3`,
        [is_visible, payload.userid, item_id]
    );

    if(result.rowCount>0) return res.json(getMessage("success"));
    else return res.json(getPopupError("Something went wrong."));
}

const updateStoreHandler = async (req, res, payload) => {
    let {store_id, name} = req.body;
    
    if(store_id == null || name == null){return res.json(getPopupError("Something went wrong."));}
    if(checkNumberError(store_id))return res.json(getPopupError("Server received inappropriate data."));

    const result = await db.query(`
        UPDATE stores
        SET name = $1 
        WHERE user_id=$2 AND store_id=$3`,
        [name, payload.userid, store_id]
    );

    if(result.rowCount>0) return res.json(getMessage("success"));
    else return res.json(getPopupError("Something went wrong."));
}

const updateItemHandler = async (req, res, payload) => {
    let {item_id, name, tax} = req.body;
    
    if(item_id == null || name == null || tax == null){return res.json(getPopupError("Something went wrong."));}
    if(checkNumberError(item_id,tax))return res.json(getPopupError("Server received inappropriate data."));

    const result = await db.query(`
        UPDATE items
        SET name = $1, default_tax=$2 
        WHERE user_id=$3 AND item_id=$4`,
        [name, tax, payload.userid, item_id]
    );
    console.log("name:"+name);
    console.log("tax:"+tax);
    console.log("userid:"+payload.userid);
    console.log("item_id:"+item_id);

    if(result.rowCount>0) return res.json(getMessage("success"));
    else return res.json(getPopupError("Something went wrong."));
}

const googleLoginHandler = async (req, res, payload) => {
    let {token_id} = req.body;
    console.log("token_id "+token_id);
    if(token_id == null){return res.json(getPopupError("Something went wrong."));}

    const google_payload = await verifyGoogleIdToken(token_id);
    if(google_payload!=null){
       let email = google_payload.email;
       email=email.toLowerCase();

       const result = await db.query('SELECT id, token_version FROM auth WHERE username = $1' ,
        [email]
       );

       if(result.rowCount==0){
        const insert_result = await db.query('INSERT INTO auth (username) VALUES ($1) RETURNING id, token_version',[email]);
        if(insert_result.rowCount==0)return res.json(getPopupError("Something went wrong."));
        const row = insert_result.rows[0];
        let r = getMessage("success");

        let token_version = Number(row.token_version);
        let refresh_token = generateRefreshToken(row.id, token_version);
    
        addRefreshCookie(res,refresh_token);
    
        r.username = email;
        return res.json(r);

       }
       else{
        const row = result.rows[0];
        let r = getMessage("success");

        let token_version = Number(row.token_version);
        let refresh_token = generateRefreshToken(row.id, token_version);
    
        addRefreshCookie(res,refresh_token);
    
        r.username = email;
        return res.json(r);
       }

       
       
    }
    else return res.json(getPopupError("Something went wrong."));
    return;
    const result = await db.query(`
        UPDATE items
        SET name = $1, default_tax=$2 
        WHERE user_id=$3 AND item_id=$4`,
        [name, tax, payload.userid, item_id]
    );
    console.log("name:"+name);
    console.log("tax:"+tax);
    console.log("userid:"+payload.userid);
    console.log("item_id:"+item_id);

    if(result.rowCount>0) return res.json(getMessage("success"));
    else return res.json(getPopupError("Something went wrong."));
}


routes={
    "/login": {GET:null, POST:loginHandler, authNeeded:false},
    "/register": {GET:null, POST:registerHandler, authNeeded:false},
    "/google_login": {GET:null, POST:googleLoginHandler, authNeeded:false},
    "/logout" : {GET:null, POST:logoutHandler, authNeeded:true},
    "/token" : {GET:null, POST:refreshAccessTokenHandler, authNeeded:false},
    "/guestregister" : {GET:null, POST:guestRegisterHandler, authNeeded:false},
    "/add_store": {GET:null, POST:addStoreHandler, authNeeded:true},
    "/get_stores": {GET:null, POST:getStoresHandler, authNeeded:true},
    "/get_store_data": {GET:null, POST:getStoreDataHandler, authNeeded:true},
    "/add_item": {GET:null, POST:addItemHandler, authNeeded:true},
    "/save_receipt": {GET:null, POST:saveReceiptHandler, authNeeded:true},
    "/get_receipt_data": {GET:null, POST:getReceiptDataHandler, authNeeded:true},
    "/get_receipts": {GET:null, POST:getReceiptsHandler, authNeeded:true},
    "/add_income_source": {GET:null, POST:addIncomeSourceHandler, authNeeded:true},
    "/set_income_source_visibility": {GET:null, POST:setIncomeSourceVisibility, authNeeded:true},
    "/update_income": {GET:null, POST:updateIncomeHandler, authNeeded:true},
    "/get_stats": {GET:null, POST:getStatsHandler, authNeeded:true},
    "/refresh_stores": {GET:null, POST:refreshStores, authNeeded:true},
    "/set_store_visibility": {GET:null, POST:setStoreVisibility, authNeeded:true},
    "/set_item_visibility": {GET:null, POST:setItemVisibility, authNeeded:true},
    "/update_store": {GET:null, POST:updateStoreHandler, authNeeded:true},
    "/update_item": {GET:null, POST:updateItemHandler, authNeeded:true},
}

app.all("/*", (req,res)=>{
    try{
        const {method, path} = req;

        const handler = routes[path] && routes[path][method];
        if(handler){
            console.log("Handling "+path);
            if(routes[path].authNeeded){
                let access_token = req.cookies.access_token;
                let refresh_token = req.cookies.refresh_token;
                if(!refresh_token)return res.json(getMessage("noToken"));
                else if(!access_token) return res.json(getMessage("tokenExpired"));
                
                const secret = process.env.JWT_ACCESS_SECRET;
                try{
                    const payload = jwt.verify(access_token, secret);
                    if (payload.userid == null) { return res.json(getPopupError("Something went wrong.")); }

                    return handler(req,res, payload);
                }
                catch(error){
                    removeAccessToken();
                    return res.json(getMessage("tokenExpired"));
                }


            }
            else return handler(req,res);
        }
        else{
            return res.status(404).json(getError("Wrong path or method."));
        }
    }   
    catch(error){
        if(error.status===429){
            return res.json(getPopupError("Too many requests. Please try again later."));
        }
        return res.json(getError(error.message));
    }
});

https.createServer(options, app).listen(PORT, () => {
    console.log(`Server running on https://localhost:${PORT}`);
});