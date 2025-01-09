using System;

namespace ISLEMLER.Events
{
    public class UserEventArgs : EventArgs
    {
        public DateTime Timestamp { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public int Age { get; set; }

        public override string ToString()
        {
            return $"User[Username={Username}, Email={Email}, Age={Age}, Timestamp={Timestamp:yyyy-MM-dd HH:mm:ss.ffffff+03}]";
        }
    } 
} 
