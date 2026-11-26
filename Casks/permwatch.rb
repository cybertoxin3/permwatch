cask "permwatch" do
  version "0.5.0"
  sha256 "050bc60572a8fab2dcaf09bb9b6e075c497a8feb9e3ed17b902767fd6af075f2"

  url "https://github.com/cybertoxin3/permwatch/releases/download/v#{version}/permwatch-#{version}.zip"
  name "permwatch"
  desc "Privacy and security monitor for app permissions, persistence and malware"
  homepage "https://github.com/cybertoxin3/permwatch"

  livecheck do
    url "https://raw.githubusercontent.com/cybertoxin3/permwatch/main/docs/appcast.xml"
    strategy :sparkle, &:short_version
  end

  auto_updates true
  depends_on macos: :sonoma

  app "permwatch.app"

  uninstall launchctl: [
              "com.yusuf.permwatch.guard",
              "com.yusuf.permwatch.root",
            ],
            quit:      "com.yusuf.permwatch"

  zap trash: [
    "/Library/Application Support/permwatch",
    "~/Library/Application Support/permwatch",
    "~/Library/Caches/com.yusuf.permwatch",
    "~/Library/HTTPStorages/com.yusuf.permwatch",
    "~/Library/Preferences/com.yusuf.permwatch.plist",
    "~/Library/Saved Application State/com.yusuf.permwatch.savedState",
  ]
end
