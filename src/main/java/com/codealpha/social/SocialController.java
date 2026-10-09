package com.codealpha.social;

import jakarta.servlet.http.HttpSession;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.util.*;

@Controller
public class SocialController {
 private final JdbcTemplate jdbc;
 private final BCryptPasswordEncoder encoder=new BCryptPasswordEncoder();
 public SocialController(JdbcTemplate jdbc){this.jdbc=jdbc;}

 @ModelAttribute("currentUser")
 public Map<String,Object> currentUser(HttpSession s){
  Object id=s.getAttribute("userId");if(id==null)return null;
  List<Map<String,Object>> rows=jdbc.queryForList("SELECT id,name,email,bio FROM users WHERE id=?",id);
  return rows.isEmpty()?null:rows.get(0);
 }
 @GetMapping("/")
 public String home(HttpSession s,Model model){
  Object uid=s.getAttribute("userId");
  model.addAttribute("posts",jdbc.queryForList("""
   SELECT p.id,p.user_id,p.content,p.created_at,u.name,
   (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS like_count,
   (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comment_count,
   CASE WHEN EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) THEN 1 ELSE 0 END AS liked
   FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC
   """,uid==null?-1L:uid));
  model.addAttribute("people",jdbc.queryForList("""
   SELECT u.id,u.name,u.bio,
   (SELECT COUNT(*) FROM follows f WHERE f.following_id=u.id) AS followers,
   (SELECT COUNT(*) FROM posts p WHERE p.user_id=u.id) AS post_count,
   CASE WHEN EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=? AND f.following_id=u.id) THEN 1 ELSE 0 END AS following
   FROM users u WHERE u.id<>? ORDER BY u.name
   """,uid==null?-1L:uid,uid==null?-1L:uid));
  model.addAttribute("comments",jdbc.queryForList("SELECT c.post_id,c.content,c.created_at,u.name FROM comments c JOIN users u ON u.id=c.user_id ORDER BY c.id"));
  return "index";
 }
 @GetMapping("/register") public String registerPage(){return "register";}
 @PostMapping("/register")
 public String register(@RequestParam String name,@RequestParam String email,@RequestParam String password,HttpSession s,RedirectAttributes f){
  if(name.isBlank()||email.isBlank()||password.length()<6){f.addFlashAttribute("error","Enter all fields and use a password of at least 6 characters.");return "redirect:/register";}
  try{jdbc.update("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)",name.trim(),email.trim().toLowerCase(),encoder.encode(password));
   Long id=jdbc.queryForObject("SELECT id FROM users WHERE email=?",Long.class,email.trim().toLowerCase());s.setAttribute("userId",id);return "redirect:/";
  }catch(Exception e){f.addFlashAttribute("error","Display name or email is already in use.");return "redirect:/register";}
 }
 @GetMapping("/login") public String loginPage(){return "login";}
 @PostMapping("/login")
 public String login(@RequestParam String email,@RequestParam String password,HttpSession s,RedirectAttributes f){
  List<Map<String,Object>> rows=jdbc.queryForList("SELECT * FROM users WHERE email=?",email.trim().toLowerCase());
  if(rows.isEmpty()||!encoder.matches(password,(String)rows.get(0).get("PASSWORD_HASH"))){f.addFlashAttribute("error","Invalid email or password.");return "redirect:/login";}
  s.setAttribute("userId",rows.get(0).get("ID"));return "redirect:/";
 }
 @PostMapping("/logout") public String logout(HttpSession s){s.invalidate();return "redirect:/";}
 @PostMapping("/posts")
 public String createPost(@RequestParam String content,HttpSession s,RedirectAttributes f){
  if(s.getAttribute("userId")==null){f.addFlashAttribute("error","Please log in to create a post.");return "redirect:/login";}
  String text=content.trim();if(text.isEmpty()||text.length()>1000){f.addFlashAttribute("error","Post must be 1–1000 characters.");return "redirect:/";}
  jdbc.update("INSERT INTO posts(user_id,content) VALUES(?,?)",s.getAttribute("userId"),text);return "redirect:/";
 }
 @PostMapping("/posts/{id}/like")
 public String like(@PathVariable long id,HttpSession s,RedirectAttributes f){
  Object uid=s.getAttribute("userId");if(uid==null){f.addFlashAttribute("error","Log in to like posts.");return "redirect:/login";}
  if(jdbc.queryForList("SELECT id FROM posts WHERE id=?",id).isEmpty())return "redirect:/";
  if(!jdbc.queryForList("SELECT user_id FROM likes WHERE user_id=? AND post_id=?",uid,id).isEmpty())jdbc.update("DELETE FROM likes WHERE user_id=? AND post_id=?",uid,id);
  else jdbc.update("INSERT INTO likes(user_id,post_id) VALUES(?,?)",uid,id);
  return "redirect:/";
 }
 @PostMapping("/posts/{id}/comments")
 public String comment(@PathVariable long id,@RequestParam String content,HttpSession s,RedirectAttributes f){
  Object uid=s.getAttribute("userId");if(uid==null){f.addFlashAttribute("error","Log in to comment.");return "redirect:/login";}
  String text=content.trim();if(text.isEmpty()||text.length()>500){f.addFlashAttribute("error","Comment must be 1–500 characters.");return "redirect:/";}
  if(jdbc.queryForList("SELECT id FROM posts WHERE id=?",id).isEmpty())return "redirect:/";
  jdbc.update("INSERT INTO comments(post_id,user_id,content) VALUES(?,?,?)",id,uid,text);return "redirect:/";
 }
 @PostMapping("/users/{id}/follow")
 public String follow(@PathVariable long id,HttpSession s,RedirectAttributes f){
  Object uid=s.getAttribute("userId");if(uid==null){f.addFlashAttribute("error","Log in to follow people.");return "redirect:/login";}
  if(((Number)uid).longValue()==id){f.addFlashAttribute("error","You cannot follow yourself.");return "redirect:/";}
  if(jdbc.queryForList("SELECT id FROM users WHERE id=?",id).isEmpty())return "redirect:/";
  if(!jdbc.queryForList("SELECT follower_id FROM follows WHERE follower_id=? AND following_id=?",uid,id).isEmpty())jdbc.update("DELETE FROM follows WHERE follower_id=? AND following_id=?",uid,id);
  else jdbc.update("INSERT INTO follows(follower_id,following_id) VALUES(?,?)",uid,id);
  return "redirect:/";
 }
 @PostMapping("/profile")
 public String updateProfile(@RequestParam String bio,HttpSession s,RedirectAttributes f){
  Object uid=s.getAttribute("userId");if(uid==null){f.addFlashAttribute("error","Log in to edit your profile.");return "redirect:/login";}
  if(bio.length()>180){f.addFlashAttribute("error","Bio must be 180 characters or fewer.");return "redirect:/";}
  jdbc.update("UPDATE users SET bio=? WHERE id=?",bio.trim(),uid);f.addFlashAttribute("success","Profile updated.");return "redirect:/";
 }
}
