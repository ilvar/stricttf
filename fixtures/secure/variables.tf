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

variable "organization_id" {
  type        = string
  description = "AWS Organizations ID whose accounts may read the logs."
}
