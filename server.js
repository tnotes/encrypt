const express = require('express');
const encrypt = require('./encrypt_key');
const app = express();
app.get('/:card',function(req,res){
	return res.send(encrypt(req.params.card));
});
app.listen(80);