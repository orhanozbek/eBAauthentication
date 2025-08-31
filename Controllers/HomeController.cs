using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using eBAauthentication.Models;
using System.Diagnostics;

namespace eBAauthentication.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                ViewBag.UserName = User.Identity.Name;
                ViewBag.FullName = User.FindFirst("FullName")?.Value;
            }

            return View();
        }

        [Authorize] // Bu sayfa sadece giriþ yapmýþ kullanýcýlar için
        public IActionResult Dashboard()
        {
            ViewBag.UserName = User.Identity?.Name;
            ViewBag.FullName = User.FindFirst("FullName")?.Value;
            return View();
        }

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