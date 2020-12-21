load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "ACTION_NAMES")
load(
    "@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    "feature",
    "flag_group",
    "flag_set",
    "tool_path",
    "with_feature_set",
)
load("@rules_cc//cc:defs.bzl", "cc_toolchain")

all_compile_actions = [
    ACTION_NAMES.c_compile,
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.linkstamp_compile,
    ACTION_NAMES.assemble,
    ACTION_NAMES.preprocess_assemble,
    ACTION_NAMES.cpp_header_parsing,
    ACTION_NAMES.cpp_module_compile,
    ACTION_NAMES.cpp_module_codegen,
    ACTION_NAMES.clif_match,
    ACTION_NAMES.lto_backend,
]

all_cpp_compile_actions = [
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.linkstamp_compile,
    ACTION_NAMES.cpp_header_parsing,
    ACTION_NAMES.cpp_module_compile,
    ACTION_NAMES.cpp_module_codegen,
    ACTION_NAMES.clif_match,
]

all_link_actions = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

def _impl(ctx):
    cpu = ctx.attr.cpu
    llvm_root = ctx.attr._llvm_root[BuildSettingInfo].value
    llvm_version = ctx.attr._llvm_version[BuildSettingInfo].value

    compiler = "clang"
    toolchain_identifier = "llvm_{}".format(cpu)
    host_system_name = "local"
    target_system_name = "local"
    target_libc = "local"
    abi_version = "local"
    abi_libc_version = "local"

    default_link_flags_feature = feature(
        name = "default_link_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = all_link_actions,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-lm",
                            "-l:libc++.a",
                            "-l:libc++abi.a",
                            "-Wl,-z,relro,-z,now",
                            "-no-canonical-prefixes",
                        ],
                    ),
                ],
            ),
            flag_set(
                actions = all_link_actions,
                flag_groups = [flag_group(flags = ["-Wl,--gc-sections"])],
                with_features = [with_feature_set(features = ["opt"])],
            ),
        ],
    )

    unfiltered_compile_flags_feature = feature(
        name = "unfiltered_compile_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = all_compile_actions,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-no-canonical-prefixes",
                            "-Wno-builtin-macro-redefined",
                            "-D__DATE__=\"redacted\"",
                            "-D__TIMESTAMP__=\"redacted\"",
                            "-D__TIME__=\"redacted\"",
                        ],
                    ),
                ],
            ),
        ],
    )

    supports_pic_feature = feature(name = "supports_pic", enabled = True)

    cxx_builtin_include_directories = [
        llvm_root + "/include/c++/v1",
        llvm_root + "/lib/clang/" + llvm_version + "/include",
        "/usr/include",
    ]

    default_compile_flags_feature = feature(
        name = "default_compile_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = all_compile_actions,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-U_FORTIFY_SOURCE",
                            "-D_FORTIFY_SOURCE=1",
                            "-fstack-protector",
                            "-Wall",
                            "-fno-omit-frame-pointer",
                        ] + [
                            "-I" + dir
                            for dir in cxx_builtin_include_directories
                        ],
                    ),
                ],
            ),
            flag_set(
                actions = all_compile_actions,
                flag_groups = [flag_group(flags = ["-g"])],
                with_features = [with_feature_set(features = ["dbg"])],
            ),
            flag_set(
                actions = all_compile_actions,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-g0",
                            "-O2",
                            "-DNDEBUG",
                            "-ffunction-sections",
                            "-fdata-sections",
                        ],
                    ),
                ],
                with_features = [with_feature_set(features = ["opt"])],
            ),
        ],
    )

    opt_feature = feature(name = "opt")
    dbg_feature = feature(name = "dbg")

    sysroot_feature = feature(
        name = "sysroot",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.lto_backend,
                    ACTION_NAMES.clif_match,
                ] + all_link_actions,
                flag_groups = [
                    flag_group(
                        flags = ["--sysroot=%{sysroot}"],
                        expand_if_available = "sysroot",
                    ),
                ],
            ),
        ],
    )

    user_compile_flags_feature = feature(
        name = "user_compile_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = all_compile_actions,
                flag_groups = [
                    flag_group(
                        flags = ["%{user_compile_flags}"],
                        iterate_over = "user_compile_flags",
                        expand_if_available = "user_compile_flags",
                    ),
                ],
            ),
        ],
    )

    features = [
        default_compile_flags_feature,
        default_link_flags_feature,
        supports_pic_feature,
        opt_feature,
        dbg_feature,
        sysroot_feature,
        user_compile_flags_feature,
        unfiltered_compile_flags_feature,
    ]

    tool_paths = [
        tool_path(name = "ar", path = llvm_root + "/bin/llvm-ar"),
        tool_path(name = "cpp", path = llvm_root + "/bin/clang++"),
        tool_path(name = "gcc", path = llvm_root + "/bin/clang"),
        tool_path(name = "gcov", path = llvm_root + "/bin/llvm-cov"),
        tool_path(name = "ld", path = llvm_root + "/bin/ld.lld"),
        tool_path(name = "nm", path = llvm_root + "/bin/llvm-nm"),
        tool_path(name = "objdump", path = llvm_root + "/bin/llvm-objdump"),
        tool_path(name = "strip", path = llvm_root + "/bin/llvm-strip"),
    ]

    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.write(out, "Fake executable")
    return [
        cc_common.create_cc_toolchain_config_info(
            ctx = ctx,
            features = features,
            action_configs = [],
            cxx_builtin_include_directories = cxx_builtin_include_directories,
            toolchain_identifier = toolchain_identifier,
            host_system_name = host_system_name,
            target_system_name = target_system_name,
            target_cpu = cpu,
            target_libc = target_libc,
            compiler = compiler,
            abi_version = abi_version,
            abi_libc_version = abi_libc_version,
            tool_paths = tool_paths,
        ),
        DefaultInfo(
            executable = out,
        ),
    ]

llvm_cc_toolchain_config = rule(
    implementation = _impl,
    attrs = {
        "cpu": attr.string(mandatory = True),
        "_llvm_root": attr.label(default = "//toolchain:llvm_root"),
        "_llvm_version": attr.label(default = "//toolchain:llvm_version"),
    },
    provides = [CcToolchainConfigInfo],
    executable = True,
)

def llvm_cc_toolchain(name, cpu):
    config_name = "llvm_cc_toolchain_config_" + name
    toolchain = llvm_cc_toolchain_config(name = config_name, cpu = cpu)

    empty_name = "llvm_toolchain_empty_" + name
    empty = native.filegroup(name = empty_name)
    empty_ref = ":" + empty_name

    cc_toolchain(
        name = name,
        all_files = empty_ref,
        compiler_files = empty_ref,
        dwp_files = empty_ref,
        linker_files = empty_ref,
        objcopy_files = empty_ref,
        strip_files = empty_ref,
        supports_param_files = 0,
        toolchain_config = ":" + config_name,
        toolchain_identifier = "llvm-toolchain-" + name,
    )
