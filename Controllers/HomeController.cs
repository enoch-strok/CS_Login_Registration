using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using CS_Login_Registration.Models;

using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
// using LoginAndRegistration.Models;
using Microsoft.AspNetCore.Identity;

namespace CS_Login_Registration.Controllers
{
    public class HomeController : Controller
    {
        private readonly MyContext _context;

        public HomeController(MyContext context)
        {
            _context = context;
        }

//-------------------------------------
//same register user works but leads to error page
//need validations to show
//login needs doesnt work with wrong password
//-------------------------------------
        [HttpGet("")]
        public IActionResult Index()
        {

            ViewBag.Users = _context.Users;

            return View();
        }
//-------------------------------------
        [HttpGet("success")]
        public IActionResult Success()
        {

            ViewBag.Users = _context.Users;
            if(HttpContext.Session.GetInt32("UserId") == null)
            {
                return RedirectToAction("Index");
            }

            return View();
        }
//------------------------------------------        
        [HttpGet("logout")]
        public IActionResult Logout()
        {

            HttpContext.Session.Clear();

            return RedirectToAction("Index");
        }
//-------------------------------------
        [HttpPost("register-process")]
        public IActionResult Register(User NewUser)
        {

            ViewBag.Users = _context.Users;
            // Check initial ModelState
            if(ModelState.IsValid)
            {
                // If a User exists with provided email
                if(_context.Users.Any(u => u.Email == NewUser.Email))
                {
                    ModelState.AddModelError("Email", "Email already in use!");
                    return View("index", NewUser);
                }
                PasswordHasher<User> Hasher = new PasswordHasher<User>();
                NewUser.Password = Hasher.HashPassword(NewUser,NewUser.Password);

                _context.Add(NewUser);
                _context.SaveChanges();
            }
        
            // HttpContext.Session.SetInt32("UserId", NewUser.UserId);
            
            return RedirectToAction("Index", NewUser);
            // other code
        }  
//-------------------------------------
        [HttpGet("login")]
        public IActionResult Login()
        {
            
            return View();
        }
//------------------------------------
        [HttpPost("login-process")]
        public IActionResult LoginProcess(LoginUser userSubmission)
        {
            if(ModelState.IsValid)
            {
                // If inital ModelState is valid, query for a user with provided email
                var userInDb = _context.Users.FirstOrDefault(u => u.Email == userSubmission.Email);
                // If no user exists with provided email
                if(userInDb == null)
                {
                    // Add an error to ModelState and return to View!
                    ModelState.AddModelError("Email", "Invalid Email/Password");
                    return View("Login");
                }
                
                // Initialize hasher object
                var hasher = new PasswordHasher<LoginUser>();
                // verify provided password against hash stored in db
                var result = hasher.VerifyHashedPassword(userSubmission, userInDb.Password, userSubmission.Password);
                
                // result can be compared to 0 for failure
                if(result == 0)
                {
                    // handle failure (this should be similar to how "existing email" is handled)
                    ModelState.AddModelError("Password", "Password Invalid");
                    return View("Login");
                }
                    HttpContext.Session.SetInt32("UserId", userInDb.UserId);
                    return RedirectToAction("Success", userSubmission);
            }
            
            return RedirectToAction("Login");
        }
//------------------------------------
//------------------------------------
//------------------------------------
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
