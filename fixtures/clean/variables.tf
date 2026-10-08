variable "region" {
  type        = string
  description = "AWS region the log bucket is created in."
}

variable "bucket_name" {
  type        = string
  description = "Globally unique name of the log bucket."

  validation {
    condition     = length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63
    error_message = "bucket_name must be between 3 and 63 characters."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment, used for tagging."
  default     = "dev"
}

variable "tags" {
  type        = map(string)
  description = "Extra tags applied to every resource."
  default     = {}
}
