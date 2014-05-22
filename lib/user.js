'use strict'
var sys = require('sys')
var exec = require('child_process').exec;
var child;
var user = {};

user.createUser = function(req, res) {
    var username = req.body.username
    if(username.indexOf(';') != -1){
        res.send('Failed');
        return;
    }
    var key = req.body.key
    console.log('Username: ' + username)
    console.log('Key: ' + key)
    function puts(error, stdout, stderr) { 
        sys.puts(stdout) 
    }
   function sleep(millis, callback) {
        setTimeout(function(){ 
            callback(); 
        }
        , millis);
    } 
    var updateAuthorized = "echo \"" + key + "\" | sudo tee -a /home/" + username + "/.ssh/authorized_keys";
    exec("sudo useradd -G users -m " + username + " -s /bin/bash ", function(error, stdout, stderr){
        if(stderr || error){
            res.send(JSON.stringify({error: 'User ' + username + ' already exists'}))
            return;
        }
        sleep( 3000, 
            exec("echo \"" + key + "\" | sudo tee -a /home/" + username + "/.ssh/authorized_keys",  function(error, stdout, stderr){
                if(stderr || error){
                    res.send(JSON.stringify({error: 'User created by ssh key could not be added. Please contact an admin. '}))
                    return;
                }
                res.send('User Created');
            })
        )
    })
}

module.exports = user
