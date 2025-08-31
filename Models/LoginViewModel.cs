using System.ComponentModel.DataAnnotations;

namespace eBAauthentication.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Email adresi gereklidir")]
        [EmailAddress(ErrorMessage = "Geçerli bir email adresi giriniz")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Şifre gereklidir")]
        [DataType(DataType.Password)]
        [Display(Name = "Şifre")]
        [MinLength(6, ErrorMessage = "Şifre en az 6 karakter olmalıdır")]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Beni hatırla")]
        public bool RememberMe { get; set; }
    }
}