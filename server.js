'use strict'
var express = require('express')
var config = require('./lib/config')
var user = require('./lib/user')
var bodyParser = require('body-parser')
var app = express()
app.use(bodyParser())
app.post('/create', user.createUser)
app.get('*', function(req,res){
    res.send('Not Found')
})
app.listen(config.app.port)
console.log('Listening on port ' + config.app.port)
