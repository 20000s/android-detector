#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <dlfcn.h>
#include <link.h>
#include "logging.h"
#include "elf_util.h"
#include "solist.h"
#include "enc_str.h"


namespace Solist {
    namespace {
        struct soinfo;

        soinfo *solist = nullptr;
        soinfo *somain = nullptr;
        std::vector<soinfo *> *preloads = nullptr;

        template<typename T>
        inline T *getStaticPointer(const SandHook::ElfImg &linker, std::string_view name) {
            auto *addr = reinterpret_cast<T **>(linker.getSymbAddress(name.data()));
            return addr == nullptr ? nullptr : *addr;
        }

        struct soinfo {
            soinfo *next() {
                return *(soinfo **) ((uintptr_t) this + solist_next_offset);
            }

            const char *get_realpath() {
                return get_realpath_sym ? get_realpath_sym(this) :
                       ((std::string *) ((uintptr_t) this + solist_realpath_offset))->c_str();
            }

            const char *get_soname() {
                return get_soname_sym ? get_soname_sym(this) :
                       *((const char **) ((uintptr_t) this + solist_realpath_offset -
                                          sizeof(void *)));
            }

            static bool setup(const SandHook::ElfImg &linker) {
                get_realpath_sym = reinterpret_cast<decltype(get_realpath_sym)>(
                        linker.getSymbAddress("__dl__ZNK6soinfo12get_realpathEv"));
                get_soname_sym = reinterpret_cast<decltype(get_soname_sym)>(
                        linker.getSymbAddress("__dl__ZNK6soinfo10get_sonameEv"));
                auto vsdo = getStaticPointer<soinfo>(linker, "__dl__ZL4vdso");
                for (size_t i = 0; i < 1024 / sizeof(void *); i++) {
                    auto *possible_next = *(void **) ((uintptr_t) solist + i * sizeof(void *));
                    if (possible_next == somain || (vsdo != nullptr && possible_next == vsdo)) {
                        solist_next_offset = i * sizeof(void *);
                        return android_get_device_api_level() < 26 ||
                               (get_realpath_sym != nullptr && get_soname_sym != nullptr);
                    }
                }
                LOGD("failed to search next offset");
                // shortcut
                return android_get_device_api_level() < 26 ||
                       (get_realpath_sym != nullptr && get_soname_sym != nullptr);
            }

#ifdef __LP64__
            inline static size_t solist_next_offset = 0x30;
            constexpr static size_t solist_realpath_offset = 0x1a8;
#else
            inline static size_t solist_next_offset = 0xa4;
            constexpr static size_t solist_realpath_offset = 0x174;
#endif

            // since Android 8
            inline static const char *(*get_realpath_sym)(soinfo *) = nullptr;

            inline static const char *(*get_soname_sym)(soinfo *) = nullptr;
        };

        const auto initialized = []() {
            SandHook::ElfImg linker("/linker");
            solist = getStaticPointer<soinfo>(linker, "__dl__ZL6solist");
            somain = getStaticPointer<soinfo>(linker, "__dl__ZL6somain");
            preloads = reinterpret_cast<std::vector<soinfo *> *>(linker.getSymbAddress(
                    "__dl__ZL13g_ld_preloads"));
            return soinfo::setup(linker) &&
                   solist != nullptr && somain != nullptr && preloads != nullptr;
        }();

        std::vector<soinfo *> linker_get_solist() {
            std::vector<soinfo *> linker_solist{};
            for (auto *iter = solist; iter; iter = iter->next()) {
                linker_solist.push_back(iter);
            }
            return linker_solist;
        }
    }

    std::string FindZygiskFromPreloads() {
        if (!preloads || preloads->empty()) return "Zygisk not found";
        for (const auto &name : *preloads) {
            if (auto realpath = name->get_realpath(); strstr(realpath, "zygisk")) {
                return "Found Zygisk loaded from:\n" + std::string(realpath);
            }
        }
        return "Zygisk not found but there's LD_PRELOAD";
    }

    std::set<std::string_view> FindPathsFromSolist(std::string_view keyword) {
        std::set<std::string_view> paths{};
        if (!initialized) {
            LOGW("%s", "not initialized");
            return paths;
        }
        for (const auto &soinfo : linker_get_solist()) {
            if (const auto &real_path = soinfo->get_realpath();
                    real_path && std::string_view(real_path).find(keyword) != std::string::npos) {
                paths.emplace(real_path);
                LOGD("Found Riru: %s", real_path);
            } else if (const auto &soname = soinfo->get_soname();
                    soname && std::string_view(soname).find(keyword) != std::string::npos) {
                paths.emplace(soname);
                LOGD("Found Riru: %s", soname);
            }
        }
        return paths;
    }
}
