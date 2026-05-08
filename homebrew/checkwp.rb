require "language/python/virtualenv"

class Checkwp < Formula
  desc "WordPress Plugin Security Checker - detect malware and vulnerabilities"
  homepage "https://gitlab.com/koljanolte/checkwp"
  url "https://github.com/koljanolte/checkwp/archive/refs/tags/v1.0.0.tar.gz"
  # Replace with the published v1.0.0 source archive checksum during the release step.
  sha256 "REPLACE_WITH_TARBALL_SHA256"
  license "MIT"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/checkwp", "--version"
  end
end
