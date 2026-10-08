variable "db_password" {
  type        = string
  description = "Master password for the database."
  sensitive   = true
}

variable "password_length" {
  type        = number
  description = "Minimum length the account password policy requires."
  default     = 16
}
