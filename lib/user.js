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
   function sleep(millis, callback) {
        setTimeout(function(){ 
            callback(); 
        }
        , millis);
    } 
    var createUser = "sudo useradd -m " + username
    var updateAuthorized = "sudo sh -c 'echo \"" + key + "\" >> /home/" + username + "/.ssh/authorized_keys'";
    exec(createUser " && " + updateAuthorized, function(error, stdout, stderr){
        if(stderr || error){
            res.send(JSON.stringify({error: error, stderr: stderr}))
            return;
        }
        /*
        sleep( 3000, 
            exec("echo \"" + key + "\" >> /home/" + username + "/.ssh/authorized_keys", function(error, stdout, stderr){
                if(stderr || error){
                    res.send(JSON.stringify({error: error, stderr: stderr}))
                    return;
                }
                res.send('User Created');
            })
        )
        */
    })
}

module.exports = user
