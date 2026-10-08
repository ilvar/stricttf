variable "db_password" {
  type        = string
  description = "Master password for the database."
  sensitive   = true
}

variable "api_token" {
  type        = string
  description = "Token the worker uses to call the upstream API."
  sensitive   = true
  default     = "tok-0123456789abcdef"
}
