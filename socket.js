module.exports = function(io){
  if(typeof io.users == "undefined"){
    io.users = [];
    io.rooms = [];  
  }
  io.sockets.on("connection", function(socket) {
    //console.log("connect");
    socket.on("connect_user", function(data) {
        //console.log(data);
        if(io.users[data.pub_id]){
          socket.user_pub_id = data.pub_id;
          io.users[data.pub_id] = socket;
          socket.emit("connect_user", { status: 0, msg:"Already connected" });
        }
        else{
          socket.emit("connect_user", { status: 1, msg:"Connected" });
          socket.user_pub_id = data.pub_id;
          io.users[data.pub_id] = socket;
        }
        var up_data = {pub_id: data.pub_id, status: 1};
        checkBlockStatus(up_data);
        getChatUnReadCounts(up_data);
        updateStatus(up_data);
        // function online status to all his users and room if he is inside
        //socket.broadcast.to(socket.room).emit('message', data);
    });

    socket.on('create_room', function (room) {
      io.rooms.push(room); // room number is the message head id
    });

    socket.on('switchRoom', function (data) {
        switchRoom(data, socket);
    });

    socket.on('online_offline', function (data) {
      updateStatus(data);
    });
    function updateStatus(data){
      const myModel = require('./model/mymodel');
      myModel.online_st(data.pub_id,data.status);
      myModel.getOnlineConnects(data.pub_id, function (connects) {
          
          if (connects.length > 0) {
            //console.log(io.users);
              for (var i = 0; i < connects.length; i++) {
                var this_socket = io.users[connects[i]];
                //console.log(i);
                //console.log(connects[i]);
                //console.log(this_socket);
                if(typeof this_socket != "undefined"){
                  //console.log(data);
                  var up_data = {user_data: data};
                  this_socket.emit("online_offline", up_data);
                }
              };
          }
      });
    }
    
    function checkBlockStatus(data){
      const myModel = require('./model/mymodel');
      myModel.getUserData(data.pub_id, function (err,user) {
        //console.log("user", user);
        if (user.length > 0 && user[0].status == 0) {
          
          var this_socket = io.users[user[0].pub_id];
          //console.log("user status", this_socket);
          if(typeof this_socket != "undefined"){
            var up_data = {
              user_pub_id: user[0].pub_id,
              status: 0
            }
            this_socket.emit("disable_user", up_data);
          }
        }
      });
    }

    function getChatUnReadCounts(data){
      const commonModel = require('./model/comman_model');
      commonModel.getMyUnreadCount(data.pub_id, function (err,chats) {
          var this_socket = io.users[data.pub_id];
          //console.log("user status", this_socket);
          if(typeof this_socket != "undefined"){
            var up_data = {
              unread_counts : chats.length
            }
            console.log(up_data);
            this_socket.emit("chat_user_counts", up_data);
          }
      });
    }

    socket.on('connect_failed', function() {
      console.log("connect failed");
    });

    socket.on('disable_user', function(data) {
      var this_socket = io.users[data.user_pub_id];
      //console.log("disable user");
      if(typeof this_socket != "undefined"){
        //console.log(data);
        data.message = "Your account has been disabled, please contact admin";
        this_socket.emit("disable_user", data);
      }
    });

    socket.on('disconnect', function () {
      console.log("disconnect");
      // function offline status to all his users and room if he is inside
      //socket.broadcast.to(socket.room).emit('message', data);
      //console.log(socket);
      data = {pub_id: socket.user_pub_id, status: 0};
      //delete io.users[socket.user_pub_id];
      //console.log(data);
      updateStatus(data);
    });

  });
  
  function switchRoom(data, socket) {
      var oldroom;
      oldroom = socket.room;
      socket.leave(socket.room);
      socket.join(data.room);
      socket.room = data.room;
  }
  return io;
}

