using System.ComponentModel.DataAnnotations;

namespace LoginAuth.Models
{
    public class ForgotPasswordModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
