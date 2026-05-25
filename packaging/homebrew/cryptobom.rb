# cryptobom Homebrew formula (prebuilt binary), generated from a template.
#
# Don't edit this file in the tap by hand: the release workflow
# (.github/workflows/release.yml, the `homebrew` job) regenerates it on every
# tagged release -- filling in the repo, version, and per-platform sha256 -- and
# commits it here. To change it, edit the template at
# packaging/homebrew/cryptobom.rb in the main repo.
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
