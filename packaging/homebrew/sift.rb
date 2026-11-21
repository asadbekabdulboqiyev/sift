# Homebrew formula for Sift.
#
# Maintained MANUALLY: .goreleaser.yaml has no `brews` section, so no release
# job updates this file. Bump url/version/sha256 together after publishing a
# tag. The sha256 below is copied from the signed v0.18.1 release checksums.txt
# (Sift_0.18.1_darwin_arm64.tar.gz) — never invent it.
#
# Test with:   brew tap asadbekabdulboqiyev/tap && brew install Sift
class Sift < Formula
  desc "Distributed load testing and network simulator written in Go"
  homepage "https://github.com/asadbekabdulboqiyev/sift"
  url "https://github.com/asadbekabdulboqiyev/sift/releases/download/v0.18.1/Sift_0.18.1_darwin_arm64.tar.gz"
  version "0.18.1"
  license "Apache-2.0"
  sha256 "2d5ad2265315a9ac4bea1536e7945840206381b5c6f7caaeb17eba27fc6233d7"
  head "https://github.com/asadbekabdulboqiyev/sift.git", branch: "main"

  # Pure Go: no system dependencies, no libpcap.
  def install
    bin.install "Sift"
  end

  def caveats
    <<~EOS
      Sift needs elevated file-descriptor limits to reach high
      virtual-user counts. macOS caps these per process; raise them with:

        sudo sysctl -w kern.maxfiles=1048576

      On Linux, use the systemd unit instead:
        LimitNOFILE=1048576
    EOS
  end

  test do
    assert_match "distributed load", shell_output("#{bin}/Sift --help")
    assert_match version.to_s, shell_output("#{bin}/Sift version")
  end
end
