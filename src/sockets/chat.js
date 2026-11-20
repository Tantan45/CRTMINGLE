const crypto = require('crypto');
const db = require('../db/database');
const { moderateText } = require('../moderation/filter');
const { chooseBestPair } = require('../matching/matcher');
const { fingerprintForRequest } = require('../security/fingerprint');

// Keep a short queue and pair eligible students randomly while respecting blocks.
function attachChat(io) {
  const queue = new Map(), rooms = new Map(), recent = new Map(), preferences = new Map();
  const onlineStudentCount=()=>new Set([...io.sockets.sockets.values()].map(client=>client.userId)).size;
  function endChat(socket,notify=true) { const room=rooms.get(socket.id); if(!room)return; rooms.delete(socket.id); const otherId=room.users.find(id=>id!==socket.id); rooms.delete(otherId); const other=io.sockets.sockets.get(otherId); if(other){other.leave(room.id);if(notify)other.emit('stranger-disconnected');} socket.leave(room.id); }
  // Prefer the pair with the most shared interests; after ten seconds relax interests.
  function tryPair() {
    const waiting=[...queue.values()],now=Date.now(),pair=chooseBestPair(waiting,db,now);
    if(pair){
      const {a,b,shared}=pair;queue.delete(a.socket.id);queue.delete(b.socket.id);
      const roomId=crypto.randomUUID(),room={id:roomId,users:[a.socket.id,b.socket.id],userIds:[a.userId,b.userId]};
      db.prepare('INSERT INTO chat_rooms(id,user_a,user_b,created_at) VALUES(?,?,?,?)').run(roomId,a.userId,b.userId,now);
      rooms.set(a.socket.id,{...room,preferences:a});rooms.set(b.socket.id,{...room,preferences:b});a.socket.join(roomId);b.socket.join(roomId);
      a.socket.emit('matched',{roomId,partnerId:b.userId,nickname:b.nickname||'Stranger',sharedInterests:shared});
      b.socket.emit('matched',{roomId,partnerId:a.userId,nickname:a.nickname||'Stranger',sharedInterests:shared});return;
    }
    // Let a waiting student know when matching opens to anyone.
    for(const item of waiting)if(item.interests.length&&now-item.queuedAt>=10_000&&!item.fallbackNotified){item.fallbackNotified=true;item.socket.emit('fallback-search');}
  }
  io.use((socket,next)=>{const user=socket.request.session?.user;if(!user)return next(new Error('Start an anonymous session first.'));const fingerprint=fingerprintForRequest(socket.request,user.deviceTokenHash),dbUser=db.prepare('SELECT accepted_rules,banned_until,fingerprint_hash FROM anonymous_sessions WHERE id=?').get(user.id),fingerprintBan=db.prepare('SELECT banned_until FROM banned_fingerprints WHERE fingerprint_hash=?').get(fingerprint);if(!dbUser||!dbUser.accepted_rules||(dbUser.banned_until&&dbUser.banned_until>Date.now())||(fingerprintBan?.banned_until>Date.now()))return next(new Error('This chat session is not eligible.'));db.prepare('UPDATE anonymous_sessions SET fingerprint_hash=?,last_seen_at=? WHERE id=?').run(fingerprint,Date.now(),user.id);socket.userId=user.id;socket.fingerprintHash=fingerprint;socket.sessionNickname='Anonymous';next();});
  io.on('connection',socket=>{
    io.emit('online-count',onlineStudentCount());
    socket.on('start',options=>{const chosen=Array.isArray(options?.interests)?options.interests.slice(0,10).map(tag=>String(tag).trim().slice(0,24)).filter(tag=>/^[\p{L}\p{N} #+_-]{1,24}$/u.test(tag)&&moderateText(tag).ok&&!moderateText(tag).redacted):[];const rawName=String(options?.nickname||'').trim();const nickname=/^[\p{L}\p{N}_ -]{2,24}$/u.test(rawName)&&moderateText(rawName).ok&&!moderateText(rawName).redacted?rawName:'';const prefs={interests:chosen,nickname};preferences.set(socket.id,prefs);queue.set(socket.id,{socket,userId:socket.userId,fingerprintHash:socket.fingerprintHash,...prefs,queuedAt:Date.now()});socket.emit('queued');tryPair();});
    socket.on('next',()=>{queue.delete(socket.id);const previous=rooms.get(socket.id)?.preferences||preferences.get(socket.id)||{interests:[],nickname:''};endChat(socket);socket.emit('notice','Finding a new student...');queue.set(socket.id,{socket,userId:socket.userId,...previous,queuedAt:Date.now()});socket.emit('queued');tryPair();});
    socket.on('stop',()=>{queue.delete(socket.id);endChat(socket);socket.emit('stopped');});
    socket.on('typing',()=>{const room=rooms.get(socket.id);if(room)socket.to(room.id).emit('typing');});
    socket.on('message',body=>{const room=rooms.get(socket.id);if(!room)return;const now=Date.now(),times=(recent.get(socket.fingerprintHash)||[]).filter(t=>now-t<10_000);if(times.length>=5)return socket.emit('notice','Please wait before sending more messages.');const checked=moderateText(body);if(!checked.ok)return socket.emit('notice',checked.reason);if(checked.redacted)socket.emit('notice','Sensitive or inappropriate content was replaced with [removed].');times.push(now);recent.set(socket.fingerprintHash,times);db.prepare('INSERT INTO chat_messages(room_id,sender_id,body,created_at) VALUES(?,?,?,?)').run(room.id,socket.userId,checked.text,now);io.to(room.id).emit('message',{senderId:socket.userId,text:checked.text,createdAt:now});});
    socket.on('disconnect',()=>{queue.delete(socket.id);endChat(socket);preferences.delete(socket.id);if(![...io.sockets.sockets.values()].some(client=>client.fingerprintHash===socket.fingerprintHash))recent.delete(socket.fingerprintHash);io.emit('online-count',onlineStudentCount());});
  });
  const fallbackPairing=setInterval(tryPair,1000);fallbackPairing.unref();
}
module.exports={attachChat};
