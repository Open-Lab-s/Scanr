class Scanr < Formula
  desc "DevSecOps security engine CLI"
  homepage "https://github.com/Open-Lab-s/Scanr"
  license "Apache-2.0"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Open-Lab-s/Scanr/releases/download/v#{version}/scanr-aarch64-apple-darwin"
      sha256 "273570306c5e11acea5578bf7373f7d3ae61ec660eb55e05c060e44d4626725c"
    else
      url "https://github.com/Open-Lab-s/Scanr/releases/download/v#{version}/scanr-x86_64-apple-darwin"
      sha256 "455ed7ccbc5d7a8739e54155e027d3ea357addfbe8553324d01ae3c99b022807"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Open-Lab-s/Scanr/releases/download/v#{version}/scanr-aarch64-unknown-linux-gnu"
      sha256 "db0f7fc35ae0917d72d8a98f2abb345f56c10ddeac3bb44fd5f5f4d89aa33bcd"
    else
      url "https://github.com/Open-Lab-s/Scanr/releases/download/v#{version}/scanr-x86_64-unknown-linux-gnu"
      sha256 "29842592118c254edcf4a437b8c4b22bc9e7fc8b47fad8ecdaa878134d57b05f"
    end
  end

  def install
    bin.install Dir["scanr*"].first => "scanr"
  end

  test do
    assert_match "scanr", shell_output("#{bin}/scanr --version").downcase
  end
end
