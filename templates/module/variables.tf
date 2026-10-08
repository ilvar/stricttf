variable "name" {
  description = "Name of the object this module manages: 2-64 lowercase letters, digits, and hyphens, starting with a letter and not ending with a hyphen."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,62}[a-z0-9]$", var.name))
    error_message = "The name must be 2-64 lowercase letters, digits, and hyphens, start with a letter, and not end with a hyphen."
  }
}

variable "tags" {
  description = "Tags merged over the module's default tags; a key given here overrides the default with the same key."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for key in keys(var.tags) : length(key) > 0])
    error_message = "Tag keys must not be empty."
  }
}
