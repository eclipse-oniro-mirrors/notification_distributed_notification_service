/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "notification_shell_command.h"

#include <getopt.h>
#include <iostream>

#include "ans_inner_errors.h"
#include "nativetoken_kit.h"
#include "notification_bundle_option.h"
#include "token_setproc.h"
#include "singleton.h"

namespace OHOS {
namespace Notification {
namespace {
constexpr char COMMAND_ACTIVE[] = "active";
constexpr char COMMAND_RECENT[] = "recent";
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
constexpr char COMMAND_DISTRIBUTED[] = "distributed";
constexpr char SHORT_OPTIONS[] = "hARDb:u:";
#else
constexpr char SHORT_OPTIONS[] = "hARb:u:";
#endif
constexpr char COMMAND_SET_RECENT_COUNT[] = "setRecentCount";
const struct option LONG_OPTIONS[] = {
    {"help", no_argument, nullptr, 'h'},
    {COMMAND_ACTIVE, no_argument, nullptr, 'A'},
    {COMMAND_RECENT, no_argument, nullptr, 'R'},
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    {COMMAND_DISTRIBUTED, no_argument, nullptr, 'D'},
#endif
    {"bundle", required_argument, nullptr, 'b'},
    {"user-id", required_argument, nullptr, 'u'},
};
constexpr char HELP_MSG[] =
    "usage: anm <command> [<options>]\n"
    "These are common commands list:\n"
    "  help                         list available commands\n"
    "  dump                         dump the info of notification\n"
    "  setting                      notification setting\n";
constexpr char DUMP_HELP_MSG[] =
    "usage: anm dump [<options>]\n"
    "options list:\n"
    "  --help, -h                   help menu\n"
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
    "  --distributed, -D            list all distributed notifications by remote device\n"
#endif
    "  --active,  -A                 list all active notifications\n"
    "  --recent,  -R                 list recent notifications\n"
    "  --bundle,  -b  <name>         dump the info filter by the specified bundle name\n"
    "  --user-id, -u  <userId>       dump the info filter by the specified userId\n";

constexpr char SETTING_SHORT_OPTIONS[] = "c:e:";
const struct option SETTING_LONG_OPTIONS[] = {
    {"help", no_argument, nullptr, 'h'},
    {"recent-count", required_argument, nullptr, 'c'},
    {"enable-notification", required_argument, nullptr, 'e'},
};
constexpr char SETTING_HELP_MSG[] =
    "usage: anm setting [<options>]\n"
    "options list:\n"
    "  --help, -h                   help menu\n"
    "  --recent-count -c <number>   set the max count of recent notifications keeping in memory\n"
    "  --enable-notification -e <bundleName:uid:enable> set notification enabled for the bundle, eg: -e com.example:10100:1\n";
}  // namespace

NotificationShellCommand::NotificationShellCommand(int argc, char *argv[]) : ShellCommand(argc, argv, "anm_dump")
{}

ErrCode NotificationShellCommand::CreateCommandMap()
{
    commandMap_ = {
        {"help", std::bind(&NotificationShellCommand::RunAsHelpCommand, this)},
        {"dump", std::bind(&NotificationShellCommand::RunAsDumpCommand, this)},
        {"setting", std::bind(&NotificationShellCommand::RunAsSettingCommand, this)},
    };
    return ERR_OK;
}

ErrCode NotificationShellCommand::Init()
{
    SetNativeToken();
    ErrCode result = OHOS::ERR_OK;
    if (!ans_) {
        ans_ = DelayedSingleton<AnsNotification>::GetInstance();
    }
    if (!ans_) {
        result = OHOS::ERR_INVALID_VALUE;
    }
    return result;
}

void NotificationShellCommand::SetNativeToken()
{
    uint64_t tokenId;
    const char **perms = new const char *[1];
    perms[0] = "ohos.permission.NOTIFICATION_CONTROLLER";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_basic",
    };

    infoInstance.processName = "anm";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    delete[] perms;
}

ErrCode NotificationShellCommand::RunAsHelpCommand()
{
    resultReceiver_.append(HELP_MSG);
    return ERR_OK;
}

ErrCode NotificationShellCommand::RunHelp()
{
    resultReceiver_.append(DUMP_HELP_MSG);
    return ERR_OK;
}

ErrCode NotificationShellCommand::RunAsDumpCommand()
{
    ErrCode ret = ERR_OK;
    std::vector<std::string> infos;
    std::string cmd;
    std::string bundle;
    int32_t userId = SUBSCRIBE_USER_INIT;
    SetDumpCmdInfo(cmd, bundle, userId, ret);
    if (ret != ERR_OK) {
        return ret;
    }
    if (cmd.empty()) {
        resultReceiver_.clear();
        resultReceiver_ = "request a option 'A' or 'R' or 'D'\n";
        resultReceiver_.append(DUMP_HELP_MSG);
        return ERR_INVALID_VALUE;
    }

    ret = RunDumpCmd(cmd, bundle, userId, infos);
    int index = 0;
    for (const auto &info : infos) {
        resultReceiver_.append("No." + std::to_string(++index) + "\n");
        resultReceiver_.append(info);
    }
    return ret;
}

ErrCode NotificationShellCommand::RunDumpCmd(const std::string& cmd, const std::string& bundle,
    int32_t userId, std::vector<std::string> &infos)
{
    if (ans_ != nullptr) {
        ErrCode ret = ans_->ShellDump(cmd, bundle, userId, infos);
        if (strncmp(cmd.c_str(), COMMAND_SET_RECENT_COUNT, strlen(COMMAND_SET_RECENT_COUNT)) == 0) {
            if (ret == ERR_OK) {
                resultReceiver_.append("set recent count success\n");
            } else {
                resultReceiver_.append("set recent count failed\n");
            }
        } else {
            resultReceiver_.append("Total:" + std::to_string(infos.size()) + "\n");
        }
        return ret;
    }
    return ERR_ANS_SERVICE_NOT_CONNECTED;
}

void NotificationShellCommand::SetDumpCmdInfo(std::string &cmd, std::string &bundle, int32_t &userId, ErrCode &ret)
{
    int option = -1;
    bool hasOption = false;
    while ((option = getopt_long(argc_, argv_, SHORT_OPTIONS, LONG_OPTIONS, nullptr)) != -1) {
        if (option == '?') {
            CheckDumpOpt();
            resultReceiver_.append(DUMP_HELP_MSG);
            ret = ERR_INVALID_VALUE;
            return;
        }
        hasOption = true;
        switch (option) {
            case 'h':
                ret = RunHelp();
                break;
            case 'A':
                cmd = COMMAND_ACTIVE;
                break;
            case 'R':
                cmd = COMMAND_RECENT;
                break;
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
            case 'D':
                cmd = COMMAND_DISTRIBUTED;
                break;
#endif
            case 'b':
                bundle = optarg;
                break;
            case 'u':
                userId = atoi(optarg);
                break;
            default:
                resultReceiver_.append(DUMP_HELP_MSG);
                break;
        }
    }
    if (!hasOption) {
        resultReceiver_.append(DUMP_HELP_MSG);
        ret = ERR_INVALID_VALUE;
    }
}

void NotificationShellCommand::CheckDumpOpt()
{
    switch (optopt) {
        case 'b':
            resultReceiver_.append("error: option 'b' requires a value.\n");
            break;
        case 'u':
            resultReceiver_.append("error: option 'u' requires a value.\n");
            break;
        default:
            resultReceiver_.append("error: unknown option.\n");
            break;
    }
}

ErrCode NotificationShellCommand::RunAsSettingCommand()
{
    int option = getopt_long(argc_, argv_, SETTING_SHORT_OPTIONS, SETTING_LONG_OPTIONS, nullptr);
    if (option == '?') {
        if (optopt == 'c') {
            resultReceiver_.append("error: option 'c' requires a value.\n");
        } else if (optopt == 'e') {
            resultReceiver_.append("error: option 'e' requires a value.\n");
        } else {
            resultReceiver_.append("error: unknown option.\n");
        }
        resultReceiver_.append(SETTING_HELP_MSG);
        return ERR_INVALID_VALUE;
    }
    if (option == 'c') {
        int32_t count = atoi(optarg);
        if ((count < NOTIFICATION_MIN_COUNT) || (count > NOTIFICATION_MAX_COUNT)) {
            resultReceiver_.append("error: recent count should between 1 and 1024\n");
            resultReceiver_.append(SETTING_HELP_MSG);
            return ERR_INVALID_VALUE;
        }
        std::vector<std::string> infos;
        std::string cmd = COMMAND_SET_RECENT_COUNT;
        cmd.append(" ").append(std::string(optarg));
        return RunDumpCmd(cmd, "", SUBSCRIBE_USER_INIT, infos);
    }
    if (option == 'e') {
        return RunSetEnableCmd();
    }

    resultReceiver_.append(SETTING_HELP_MSG);
    return ERR_INVALID_VALUE;
}

ErrCode NotificationShellCommand::RunSetEnableCmd()
{
    if (ans_ == nullptr) {
        resultReceiver_.append("error: object is null\n");
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    NotificationBundleOption bundleOption;
    std::string info = std::string(optarg);
    if (std::count(info.begin(), info.end(), ':') != 2) {  // 2 (bundleName:uid:enable)
        resultReceiver_.append("error: setting information error\n");
        resultReceiver_.append(SETTING_HELP_MSG);
        return ERR_INVALID_VALUE;
    }

    size_t pos = info.find(':');
    bundleOption.SetBundleName(info.substr(0, pos));
    info = info.substr(pos + 1);
    pos = info.find(':');
    bundleOption.SetUid(atoi(info.substr(0, pos).c_str()));
    bool enable = atoi(info.substr(pos + 1).c_str());

    ErrCode ret = ans_->SetNotificationsEnabledForSpecifiedBundle(bundleOption, "", enable);
    if (ret == ERR_OK) {
        resultReceiver_.append("set notification enabled success\n");
    } else {
        resultReceiver_.append("set notification enabled failed\n");
    }
    return ret;
}
}  // namespace Notification
}  // namespace OHOS
