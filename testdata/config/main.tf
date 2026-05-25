# Terraform TLS/KMS sample for cryptobom regression testing.

resource "aws_lb_listener" "https" {
  # ELB policy that allows TLS 1.1 — flagged.
  ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
}

resource "aws_cloudfront_distribution" "cdn" {
  viewer_certificate {
    # CloudFront minimum protocol with a _year suffix — flagged.
    minimum_protocol_version = "TLSv1.1_2016"
  }
}

resource "aws_kms_key" "rsa" {
  # Quantum-vulnerable KMS key.
  customer_master_key_spec = "RSA_2048"
}

resource "aws_lb_listener" "modern" {
  # Modern policy — must NOT be flagged.
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}
