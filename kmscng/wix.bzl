_WIX_BUILD_FILE_CONTENT = """
package(default_visibility = ["//visibility:public"])

filegroup(name = "all", srcs = glob(["wix/**/*"]))
alias(name = "candle", actual = "wix/bin/candle.exe")
alias(name = "light", actual = "wix/bin/light.exe")
"""

def _wix_impl(repo_ctx):
    location = repo_ctx.os.environ.get(
        "WIX_LOCATION",
        default = "C:\\Program Files (x86)\\WiX Toolset v3.11",
    )
    if not repo_ctx.path(location).exists:
        fail("Could not find WiX Toolset at %s", location)
    repo_ctx.symlink(location, "wix")
    repo_ctx.file(
        "BUILD.bazel",
        content = _WIX_BUILD_FILE_CONTENT,
    )

wix = repository_rule(
    implementation = _wix_impl,
    environ = ["WIX_LOCATION"],
)
