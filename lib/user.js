'use strict'
var sys = require('sys')
var exec = require('child_process').exec;
var child;
var user = {};

user.createUser = function(req, res) {
    var username = req.body.u
    if(username.indexOf(';') != -1){
        res.send('Failed');
        return;
    }
    var key = req.body.k
    console.log('Username: ' + username)
    console.log('Key: ' + key)
    function puts(error, stdout, stderr) { 
        sys.puts(stdout) 
    }
    exec("useradd -m " + username, function(error, stdout, stderr){
        if(stderr || error){
            res.send('Error')
            return;
        }
        exec("echo \"" + key + "\" >> /home/" + username + "/.ssh/authorized_keys")
        res.send('User Created');
    })
}

module.exports = user
