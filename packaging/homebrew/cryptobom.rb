# cryptobom Homebrew formula (prebuilt-binary).
#
# This is a TEMPLATE. The release workflow (.github/workflows/release.yml, the
# `homebrew` job) renders the __PLACEHOLDERS__ on each tagged release and pushes
# the result to your tap repo as Formula/cryptobom.rb. To bootstrap by hand,
# replace __REPO__ (owner/repo), __VERSION__ (the tag without the leading "v"),
# and the three __SHA_*__ values (from the release's checksums.txt).
#
# A prebuilt binary is shipped rather than built from source because the parsers
# use tree-sitter via cgo: the binary is platform-specific and needs a C
# toolchain, so we install the artifacts already built on native CI runners.
class Cryptobom < Formula
  desc "Developer-first cryptographic discovery for the post-quantum transition"
  homepage "https://github.com/__REPO__"
  version "__VERSION__"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/__REPO__/releases/download/v#{version}/cryptobom-v#{version}-darwin-arm64.tar.gz"
      sha256 "__SHA_DARWIN_ARM64__"
    end
    on_intel do
      url "https://github.com/__REPO__/releases/download/v#{version}/cryptobom-v#{version}-darwin-amd64.tar.gz"
      sha256 "__SHA_DARWIN_AMD64__"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/__REPO__/releases/download/v#{version}/cryptobom-v#{version}-linux-amd64.tar.gz"
      sha256 "__SHA_LINUX_AMD64__"
    end
  end

  def install
    # The release tarball contains a single top-level directory, which Homebrew
    # unpacks into; the binary sits at its root next to LICENSE and README.md.
    bin.install "cryptobom"
  end

  test do
    assert_match "cryptobom v#{version}", shell_output("#{bin}/cryptobom version")
  end
end
