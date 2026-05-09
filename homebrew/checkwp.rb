require "language/python/virtualenv"

class Checkwp < Formula
  desc "Offline-first WordPress plugin malware and vulnerability scanner"
  homepage "https://checkwp.org"
  url "https://files.pythonhosted.org/packages/source/c/checkwp/checkwp-1.1.0.tar.gz"
  # Replace with the published 1.1.0 source archive checksum during the release step.
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
