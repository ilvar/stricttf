variable "region" {
  type        = "string"
  description = "AWS region to deploy into."
}

variable "settings" {
  type        = map(any)
  description = ""
}

variable "instanceCount" {
  description = "How many bootstrap runs to perform."
}

variable "db_password" {
  type        = string
  description = "Master password for the database."
}

variable "legacy_flag" {
  type        = bool
  description = "A switch nothing reads any more."
}
