class Scanr < Formula
  desc "DevSecOps security engine CLI"
  homepage "https://github.com/scanr-dev/scanr"
  license "Apache-2.0"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/scanr-dev/scanr/releases/download/v#{version}/scanr-aarch64-apple-darwin"
      sha256 "REPLACE_WITH_SHA256"
    else
      url "https://github.com/scanr-dev/scanr/releases/download/v#{version}/scanr-x86_64-apple-darwin"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/scanr-dev/scanr/releases/download/v#{version}/scanr-aarch64-unknown-linux-gnu"
      sha256 "REPLACE_WITH_SHA256"
    else
      url "https://github.com/scanr-dev/scanr/releases/download/v#{version}/scanr-x86_64-unknown-linux-gnu"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  def install
    bin.install Dir["scanr*"].first => "scanr"
  end

  test do
    assert_match "scanr", shell_output("#{bin}/scanr --version").downcase
  end
end
