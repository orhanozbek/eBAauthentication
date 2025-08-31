using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using eBAauthentication.Models;

namespace eBAauthentication.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            // Eğer kullanıcı zaten giriş yapmışsa ana sayfaya yönlendir
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Index", "Home");
            }

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            if (ModelState.IsValid)
            {
                // Demo için basit authentication kontrolü
                // Gerçek uygulamada database'den kullanıcı kontrolü yapılmalı
                if (IsValidUser(model.Email, model.Password))
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, model.Email),
                        new Claim(ClaimTypes.Email, model.Email),
                        new Claim("FullName", GetUserFullName(model.Email))
                    };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = model.RememberMe,
                        ExpiresUtc = model.RememberMe ?
                            DateTimeOffset.UtcNow.AddDays(30) :
                            DateTimeOffset.UtcNow.AddMinutes(20)
                    };

                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity), authProperties);

                    // Başarılı giriş loglaması
                    Console.WriteLine($"Kullanıcı giriş yaptı: {model.Email}");

                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    {
                        return Redirect(returnUrl);
                    }
                    else
                    {
                        return RedirectToAction("Index", "Home");
                    }
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Geçersiz email veya şifre.");
                }
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        // Demo kullanıcı kontrol metodu
        private bool IsValidUser(string email, string password)
        {
            // Demo hesapları - Gerçek uygulamada database kontrolü yapılmalı
            var demoUsers = new Dictionary<string, string>
            {
                { "admin@test.com", "123456" },
                { "user@ebatest.com", "password123" },
                { "demo@ebaauth.com", "demo2024" }
            };

            return demoUsers.ContainsKey(email) && demoUsers[email] == password;
        }

        // Demo kullanıcı adı getirme metodu
        private string GetUserFullName(string email)
        {
            var userNames = new Dictionary<string, string>
            {
                { "admin@test.com", "Admin Kullanıcı" },
                { "user@ebatest.com", "Test Kullanıcısı" },
                { "demo@ebaauth.com", "Demo Kullanıcı" }
            };

            return userNames.ContainsKey(email) ? userNames[email] : "Bilinmeyen Kullanıcı";
        }
    }
}