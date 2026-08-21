/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <string>
#include <cstdint>
#include <memory>

#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "command_output.h"
#include "nativetoken_kit.h"
#include "notification_bundle_option.h"
#include "notification.h"
#include "notification_request.h"
#include "notification_content.h"
#include "notification_normal_content.h"
#include "notification_long_text_content.h"
#include "notification_multiline_content.h"
#include "notification_picture_content.h"
#include "notification_conversational_content.h"
#include "notification_conversational_message.h"
#include "message_user.h"
#include "notification_media_content.h"
#include "notification_live_view_content.h"
#include "notification_local_live_view_content.h"
#include "notification_action_button.h"
#include "notification_flags.h"
#include "notification_helper.h"
#include "want_params.h"
#include "want_params_wrapper.h"
#include "token_setproc.h"

using json = nlohmann::json;

namespace OHOS {
namespace Notification {
namespace {
constexpr size_t MAX_LABEL_LEN = 204;
constexpr size_t MAX_TITLE_LEN = 1024;
constexpr size_t MAX_CONTENT_TEXT_LEN = 3072;
constexpr uint32_t MAX_SLOT_FLAGS = 0b111111;
constexpr const char* PERM_CONTROLLER = "ohos.permission.NOTIFICATION_CONTROLLER";
constexpr const char* PERM_CONTROLLER_AND_AGENT =
    "ohos.permission.NOTIFICATION_CONTROLLER 和 ohos.permission.NOTIFICATION_AGENT_CONTROLLER";

std::string TruncateString(const std::string &str, size_t maxLen)
{
    return str.size() > maxLen ? str.substr(0, maxLen) : str;
}

constexpr char SHORT_OPTIONS_PUBLISH[] = "h";
const struct option LONG_OPTIONS_PUBLISH[] = {
    {"notificationId", required_argument, nullptr, 1},
    {"notificationContent", required_argument, nullptr, 2},
    {"slotType", required_argument, nullptr, 3},
    {"label", required_argument, nullptr, 4},
    {"groupName", required_argument, nullptr, 5},
    {"badgeNumber", required_argument, nullptr, 6},
    {"updateOnly", no_argument, nullptr, 7},
    {"appMessageId", required_argument, nullptr, 8},
    {"priorityNotificationType", required_argument, nullptr, 9},
    {"alertOneTime", no_argument, nullptr, 10},
    {"sound", required_argument, nullptr, 11},
    {"autoDeletedTime", required_argument, nullptr, 12},
    {"notificationFlags", required_argument, nullptr, 13},
    {"help", no_argument, nullptr, 'h'},
    {nullptr, 0, nullptr, 0},
};

constexpr char SHORT_OPTIONS_CANCEL_BY_ID[] = "o:i:h";
const struct option LONG_OPTIONS_CANCEL_BY_ID[] = {
    {"bundleOption", required_argument, nullptr, 'o'},
    {"notificationId", required_argument, nullptr, 'i'},
    {"help", no_argument, nullptr, 'h'},
    {nullptr, 0, nullptr, 0},
};

constexpr char SHORT_OPTIONS_ENABLE_NOTIFICATION[] = "o:e:h";
const struct option LONG_OPTIONS_ENABLE_NOTIFICATION[] = {
    {"bundleOption", required_argument, nullptr, 'o'},
    {"enabled", no_argument, nullptr, 'e'},
    {"help", no_argument, nullptr, 'h'},
    {nullptr, 0, nullptr, 0},
};

constexpr char SHORT_OPTIONS_SET_SLOT_FLAGS[] = "o:f:h";
const struct option LONG_OPTIONS_SET_SLOT_FLAGS[] = {
    {"bundleOption", required_argument, nullptr, 'o'},
    {"flags", required_argument, nullptr, 'f'},
    {"help", no_argument, nullptr, 'h'},
    {nullptr, 0, nullptr, 0},
};

constexpr char SHORT_OPTIONS_BATCH_CANCEL[] = "a:h";
const struct option LONG_OPTIONS_BATCH_CANCEL[] = {
    {"hashcodes", required_argument, nullptr, 'a'},
    {"help", no_argument, nullptr, 'h'},
    {nullptr, 0, nullptr, 0},
};

constexpr char SHORT_OPTIONS_LIST_ALL_NOTIFICATION[] = "h";
const struct option LONG_OPTIONS_LIST_ALL_NOTIFICATION[] = {
    {"help", no_argument, nullptr, 'h'},
    {nullptr, 0, nullptr, 0},
};

constexpr char SHORT_OPTIONS_CANCEL_BY_BUNDLE[] = "o:h";
const struct option LONG_OPTIONS_CANCEL_BY_BUNDLE[] = {
    {"bundleOption", required_argument, nullptr, 'o'},
    {"help", no_argument, nullptr, 'h'},
    {nullptr, 0, nullptr, 0},
};

constexpr char HELP_MSG[] =
    "ohos-notificationManager - OpenHarmony 通知管理工具。用于通知的发布、取消、移除及查询活跃通知，"
    "不支持通知订阅及交互式UI操作。\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager <command> [options]\n"
    "\n"
    "Parameters:\n"
    "  --help                  显示帮助信息\n"
    "\n"
    "SubCommands:\n"
    "  help                    显示帮助信息\n"
    "  publish                 发布通知到系统\n"
    "  cancelById              按bundle和通知ID取消通知\n"
    "  cancelByBundle          取消指定bundle的所有通知\n"
    "  batchCancel             按哈希码批量取消通知\n"
    "  enableNotification      设置bundle的通知启用/禁用状态\n"
    "  setSlotFlags            设置bundle的通知渠道标志\n"
    "  listAllNotification     列出所有活跃通知\n"
    "\n"
    "Examples:\n"
    "  ohos-notificationManager --help\n"
    "  ohos-notificationManager publish --help\n";

constexpr char PUBLISH_HELP_MSG[] =
    "ohos-notificationManager publish - 发布通知。用于向系统发送通知，不支持订阅类通知。\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager publish --notificationContent <json> [options]\n"
    "\n"
    "Parameters:\n"
    "  --notificationContent <json>     通知内容JSON字符串（必填）\n"
    "                               所有类型公共必填: title(≤1024B), text(≤3072B)\n"
    "                               公共可选: additionalText(≤3072B)；所有属性超长截取\n"
    "                               type仅支持basic、long_text、multiline:\n"
    "                               basic示例: {\"type\":\"basic\",\"title\":\"通知标题\",\"text\":\"通知内容\",\"additionalText\":\"附加文本\"}\n"
    "                               long_text: longText(≤3072B)、expandedTitle(≤1024B)、briefText(≤1024B)，超长截取\n"
    "                                 示例: {\"type\":\"long_text\",\"title\":\"通知标题\",\"text\":\"短内容\",\"longText\":\"长文本内容\","
    "\"expandedTitle\":\"展开标题\",\"briefText\":\"摘要\",\"additionalText\":\"附加文本\"}\n"
    "                               multiline: expandedTitle(≤1024B)、briefText(≤1024B)、lines(≤3个元素,每个≤1024B)，超长截取\n"
    "                                 示例: {\"type\":\"multiline\",\"title\":\"通知标题\",\"text\":\"通知内容\","
    "\"expandedTitle\":\"展开标题\",\"briefText\":\"摘要\",\"lines\":[\"第一行\",\"第二行\",\"第三行\"],\"additionalText\":\"附加文本\"}\n"
    "  --notificationId <id>            通知ID（可选，默认: 0）\n"
    "  --slotType <type>                通知渠道类型（可选，默认: 3）\n"
    "                               0=社交通信, 1=服务提醒, 2=内容信息, 3=其他, 6=客服消息\n"
    "                               不支持4=自定义、5=实况通知、7=紧急信息\n"
    "  --updateOnly                     仅更新已存在的通知，不创建新通知（可选，标志）\n"
    "  --appMessageId <id>              应用消息ID，用于标识特定消息（可选）\n"
    "  --priorityNotificationType <type> 优先级通知类型（可选）\n"
    "                               枚举值: OTHER(非优先级通知)、PRIMARY_CONTACT(重要联系人)、AT_ME(有人@我)、"
    "URGENT_MESSAGE(紧急消息)、SCHEDULE_REMINDER(日程提醒)\n"
    "  --alertOneTime                   仅提醒一次，后续更新不再提醒（可选，标志）\n"
    "  --sound <uri>                    自定义通知声音URI（可选）\n"
    "  --badgeNumber <number>           通知角标增加数量（可选，必须>=0）\n"
    "  --autoDeletedTime <ms>           自动删除时间（毫秒，可选）\n"
    "  --label <label>                  通知标签（可选，不超过204字节）\n"
    "  --groupName <name>               通知分组名称（可选，不超过204字节，超长截取）\n"
    "  --notificationFlags <json>       通知提醒标志JSON字符串（可选）\n"
    "                               支持字段: soundEnabled(声音)、vibrationEnabled(振动)、bannerEnabled(横幅)、lockScreenEnabled(锁屏)\n"
    "                               值枚举: 2=CLOSE(关闭)。示例: {\"soundEnabled\":2,\"vibrationEnabled\":2}\n"
    "  --help                           显示帮助信息\n"
    "\n"
    "Examples:\n"
    "  # 发布基础通知\n"
    "  ohos-notificationManager publish --notificationContent \"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"Test\\\",\\\"text\\\":\\\"Hello\\\"}\"\n"
    "  # 指定渠道类型发布\n"
    "  ohos-notificationManager publish --notificationContent \"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"Alert\\\",\\\"text\\\":\\\"Content\\\"}\" --slotType 1\n";

constexpr char CANCEL_BY_ID_HELP_MSG[] =
    "ohos-notificationManager cancelById - 按bundle和通知ID取消通知。用于管理指定应用的通知，"
    "不支持无bundle信息的取消。\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager cancelById --bundleOption <json> --notificationId <id>\n"
    "\n"
    "Parameters:\n"
    "  --bundleOption <json>  目标应用信息JSON字符串（必填），包含bundleName(应用包名)和uid(应用UID)两个属性\n"
    "                         示例: \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"\n"
    "  --notificationId <id>  待取消的通知ID（必填，整数）\n"
    "  --help                 显示帮助信息\n"
    "\n"
    "Examples:\n"
    "  # 按bundle取消通知\n"
    "  ohos-notificationManager cancelById --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --notificationId 1\n";

constexpr char BATCH_CANCEL_HELP_MSG[] =
    "ohos-notificationManager batchCancel - 按哈希码批量取消通知。用于取消由哈希码标识的指定通知。\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager batchCancel --hashcodes <json>\n"
    "\n"
    "Parameters:\n"
    "  --hashcodes <json>       通知哈希码JSON数组字符串（必填），指定要移除的通知列表\n"
    "                           示例: [\"hash1\",\"hash2\",\"hash3\"]\n"
    "  --help                   显示帮助信息\n"
    "\n"
    "Examples:\n"
    "  # 按哈希码批量取消通知\n"
    "  ohos-notificationManager batchCancel --hashcodes \"[\\\"hash1\\\",\\\"hash2\\\"]\"\n";

constexpr char CANCEL_BY_BUNDLE_HELP_MSG[] =
    "ohos-notificationManager cancelByBundle - 取消指定bundle的所有通知。用于批量取消指定应用的通知。\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager cancelByBundle --bundleOption <json>\n"
    "\n"
    "Parameters:\n"
    "  --bundleOption <json>  目标应用信息JSON字符串（必填），包含bundleName(应用包名)和uid(应用UID)两个属性\n"
    "                         示例: \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"\n"
    "  --help                 显示帮助信息\n"
    "\n"
    "Examples:\n"
    "  # 取消指定bundle的所有通知\n"
    "  ohos-notificationManager cancelByBundle --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"";

constexpr char ENABLE_NOTIFICATION_HELP_MSG[] =
    "ohos-notificationManager enableNotification - 设置bundle的通知启用/禁用状态。"
    "用于控制应用的通知权限，不支持无bundle信息的设置。\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager enableNotification --bundleOption <json> --enabled <true|false>\n"
    "\n"
    "Parameters:\n"
    "  --bundleOption <json>  目标应用信息JSON字符串（必填），包含bundleName(应用包名)和uid(应用UID)两个属性\n"
    "                         示例: \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"\n"
    "  --enabled <true|false> 通知开关状态（必填，true=启用, false=禁用）\n"
    "  --help                 显示帮助信息\n"
    "\n"
    "Examples:\n"
    "  # 启用bundle的通知\n"
    "  ohos-notificationManager enableNotification --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --enabled true\n"
    "  # 禁用bundle的通知\n"
    "  ohos-notificationManager enableNotification --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --enabled false\n";

constexpr char SET_SLOT_FLAGS_HELP_MSG[] =
    "ohos-notificationManager setSlotFlags - 设置bundle的通知渠道标志。"
    "用于配置应用的通知提醒方式，不支持无bundle信息的设置。\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager setSlotFlags --bundleOption <json> --flags <flags>\n"
    "\n"
    "Parameters:\n"
    "  --bundleOption <json>  目标应用信息JSON字符串（必填），包含bundleName(应用包名)和uid(应用UID)两个属性\n"
    "                         示例: \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"\n"
    "  --flags <flags>        渠道标志位掩码（必填，uint32，十进制或0x前缀十六进制）\n"
    "                          仅bit0-bit5有效:\n"
    "                          bit0=声音, bit1=锁屏, bit2=横幅, bit3=亮屏, bit4=振动, bit5=状态栏图标\n"
    "                          必须>=0且不能大于0b111111(63)\n"
    "                          注意: 亮屏(bit3)和状态栏图标(bit5)设置关闭不会生效，服务端会强制保持开启\n"
    "  --help                 显示帮助信息\n"
    "\n"
    "Examples:\n"
    "  # 设置所有提醒标志\n"
    "  ohos-notificationManager setSlotFlags --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --flags 63\n"
    "  # 使用十六进制格式设置标志\n"
    "  ohos-notificationManager setSlotFlags --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --flags 0x3F\n";

constexpr char LIST_ALL_NOTIFICATION_HELP_MSG[] =
    "ohos-notificationManager listAllNotification - 列出所有活跃通知。"
    "用于查询当前通知状态，不支持查询其他用户的通知。\n"
    "\n"
    "每条通知输出字段:\n"
    "  notificationId          通知ID\n"
    "  createTime              通知创建时间（毫秒时间戳）\n"
    "  ownerUid                通知创建者UID\n"
    "  ownerUserId             通知创建者UserId\n"
    "  ownerBundleName         通知创建者包名\n"
    "  label                   通知标签\n"
    "  appInstanceKey          应用实例Key\n"
    "  slotType                渠道类型值\n"
    "  notificationContent     通知内容对象（按type字段区分不同类型）:\n"
    "                           公共字段: type(类型名)、title(标题)、text(文本)、additionalText(附加文本，可选)\n"
    "                           basic: 仅公共字段\n"
    "                           long_text: +longText(长文本)、expandedTitle(展开标题)、briefText(摘要)\n"
    "                           multiline: +expandedTitle(展开标题)、briefText(摘要)、lines(行文本数组)\n"
    "                           picture: +expandedTitle(展开标题)、briefText(摘要)\n"
    "                           conversation: +conversationTitle(会话标题)、isGroup(是否群聊)、messages(消息数组)\n"
    "                           media: +shownActions(展示按钮序号数组)\n"
    "                           live_view: +liveViewStatus(实况状态)、version(版本号)\n"
    "                           local_live_view: +liveViewType(实况类型)\n"
    "  actionButtons           操作按钮列表（title）\n"
    "  notificationFlags       通知提醒标志（soundEnabled/vibrationEnabled/bannerEnabled/lockScreenEnabled）\n"
    "  hashCode                通知哈希码\n"
    "\n"
    "Parameters:\n"
    "  --help                  显示帮助信息\n"
    "\n"
    "Examples:\n"
    "  # 列出所有活跃通知\n"
    "  ohos-notificationManager listAllNotification\n";
}

NotificationShellCommand::NotificationShellCommand(int argc, char *argv[]) : ShellCommand(argc, argv, "ohos-notificationManager")
{}

ErrCode NotificationShellCommand::CreateCommandMap()
{
    commandMap_ = {
        {"help", std::bind(&NotificationShellCommand::RunAsHelpCommand, this)},
        {"publish", std::bind(&NotificationShellCommand::RunAsPublishCommand, this)},
        {"cancelById", std::bind(&NotificationShellCommand::RunAsCancelByIdCommand, this)},
        {"cancelByBundle", std::bind(&NotificationShellCommand::RunAsCancelByBundleCommand, this)},
        {"batchCancel", std::bind(&NotificationShellCommand::RunAsBatchCancelCommand, this)},
        {"enableNotification", std::bind(&NotificationShellCommand::RunAsEnableNotificationCommand, this)},
        {"setSlotFlags", std::bind(&NotificationShellCommand::RunAsSetSlotFlagsCommand, this)},
        {"listAllNotification", std::bind(&NotificationShellCommand::RunAsListAllNotificationCommand, this)},
    };
    return ERR_OK;
}

ErrCode NotificationShellCommand::Init()
{
    ErrCode result = OHOS::ERR_OK;
    if (!ans_) {
        ans_ = AnsNotification::GetInstance();
    }
    if (!ans_) {
        result = OHOS::ERR_INVALID_VALUE;
    }
    return result;
}

ErrCode NotificationShellCommand::RunAsHelpCommand()
{
    if (!argList_.empty()) {
        std::string subCmd = argList_[0];
        if (subCmd == "publish") {
            resultReceiver_.append(PUBLISH_HELP_MSG);
            return ERR_OK;
        } else if (subCmd == "cancelById") {
            resultReceiver_.append(CANCEL_BY_ID_HELP_MSG);
            return ERR_OK;
        } else if (subCmd == "batchCancel") {
            resultReceiver_.append(BATCH_CANCEL_HELP_MSG);
            return ERR_OK;
        } else if (subCmd == "cancelByBundle") {
            resultReceiver_.append(CANCEL_BY_BUNDLE_HELP_MSG);
            return ERR_OK;
        } else if (subCmd == "enableNotification") {
            resultReceiver_.append(ENABLE_NOTIFICATION_HELP_MSG);
            return ERR_OK;
        } else if (subCmd == "setSlotFlags") {
            resultReceiver_.append(SET_SLOT_FLAGS_HELP_MSG);
            return ERR_OK;
        } else if (subCmd == "listAllNotification") {
            resultReceiver_.append(LIST_ALL_NOTIFICATION_HELP_MSG);
            return ERR_OK;
        }
    }
    resultReceiver_.append(HELP_MSG);
    return ERR_OK;
}

ErrCode NotificationShellCommand::ParseBundleOption(const std::string &jsonStr,
    NotificationBundleOption &bundleOption)
{
    std::string bundleName;
    int32_t uid = -1;
    if (!jsonStr.empty()) {
        if (!json::accept(jsonStr)) {
            OutputError("ERR_ARG_INVALID", "bundleOption参数解析失败: JSON格式无效",
                "请提供有效的JSON字符串。示例: --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"",
                resultReceiver_);
            return ERR_INVALID_VALUE;
        }
        auto bundleOptionJson = json::parse(jsonStr);
        if (!bundleOptionJson.is_object()) {
            OutputError("ERR_ARG_INVALID", "bundleOption必须是JSON对象",
                "请提供JSON对象格式。示例: --bundleOption "
                "\"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"",
                resultReceiver_);
            return ERR_INVALID_VALUE;
        }
        if (bundleOptionJson.contains("bundleName") && bundleOptionJson["bundleName"].is_string()) {
            bundleName = bundleOptionJson["bundleName"].get<std::string>();
        }
        if (bundleOptionJson.contains("uid") && bundleOptionJson["uid"].is_number_integer()) {
            uid = bundleOptionJson["uid"].get<int32_t>();
        }
    }
    if (bundleName.empty()) {
        OutputError("ERR_ARG_MISSING", "bundleOption中bundleName缺失: 必须提供目标应用包名",
            "请提供包含bundleName的JSON参数。示例: --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (uid < 0) {
        OutputError("ERR_ARG_MISSING", "bundleOption中uid缺失或无效: 必须提供有效的应用UID",
            "请提供包含uid的JSON参数。示例: --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    bundleOption = NotificationBundleOption(bundleName, uid);
    return ERR_OK;
}

ErrCode NotificationShellCommand::ParsePublishOptions(PublishOptions &opts)
{
    optind = 0;
    int option = getopt_long(argc_, argv_, SHORT_OPTIONS_PUBLISH, LONG_OPTIONS_PUBLISH, nullptr);
    while (option != -1) {
        switch (option) {
            case 'h':
                resultReceiver_.append(PUBLISH_HELP_MSG);
                opts.helpRequested = true;
                return ERR_OK;
            case 1: opts.notificationId = atoi(optarg); break;
            case 2: opts.contentJson = optarg; break;
            case 3: opts.slotType = atoi(optarg); break;
            case 4: opts.label = optarg; break;
            case 5: opts.groupName = optarg; break;
            case 6: opts.badgeNumber = static_cast<uint32_t>(atoi(optarg)); break;
            case 7: opts.isUpdateOnly = true; break;
            case 8: opts.appMessageId = optarg; break;
            case 9: opts.priorityNotificationType = optarg; break;
            case 10: opts.isAlertOneTime = true; break;
            case 11: opts.sound = optarg; break;
            case 12: opts.autoDeletedTime = static_cast<int64_t>(atoll(optarg)); break;
            case 13: opts.flagsStr = optarg; break;
            default:
                OutputError("ERR_UNKNOWN_OPTION", "未知选项: publish命令不支持该选项",
                    "请使用 --help 查看可用选项。示例: ohos-notificationManager publish --help", resultReceiver_);
                return ERR_INVALID_VALUE;
        }
        option = getopt_long(argc_, argv_, SHORT_OPTIONS_PUBLISH, LONG_OPTIONS_PUBLISH, nullptr);
    }
    return ERR_OK;
}

ErrCode NotificationShellCommand::ValidatePublishRequiredOptions(const PublishOptions &opts)
{
    if (opts.contentJson.empty()) {
        OutputError("ERR_ARG_MISSING", "通知内容（--notificationContent）缺失: 必须提供通知内容JSON",
            "请提供通知内容参数。示例: ohos-notificationManager publish --notificationId 1 "
            "--notificationContent \"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"Test\\\",\\\"text\\\":\\\"Hello\\\"}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (opts.slotType < 0 || opts.slotType > 7 || opts.slotType == 4 || opts.slotType == 5 || opts.slotType == 7) {
        OutputError("ERR_ARG_INVALID",
            "渠道类型无效: 渠道类型必须在 0-7 范围内且不支持 4(CUSTOM)、5(LIVE_VIEW)、7(EMERGENCY_INFORMATION)",
            "请使用有效的渠道类型值。示例: --slotType 3（OTHER类型）或 --slotType 6（CUSTOMER_SERVICE类型)",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (opts.badgeNumber > 0x7FFFFFFFu) {
        OutputError("ERR_ARG_INVALID", "badgeNumber参数值无效: 必须为非负整数",
            "请使用有效的非负整数。示例: --badgeNumber 1", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

void NotificationShellCommand::ApplySimplePublishFields(const PublishOptions &opts,
    NotificationRequest &request)
{
    if (opts.isUpdateOnly) {
        request.SetUpdateOnly(true);
    }
    if (!opts.appMessageId.empty()) {
        request.SetAppMessageId(opts.appMessageId);
    }
    if (!opts.priorityNotificationType.empty()) {
        request.SetPriorityNotificationType(opts.priorityNotificationType);
    }
    if (opts.isAlertOneTime) {
        request.SetAlertOneTime(true);
    }
    if (!opts.sound.empty()) {
        request.SetSound(opts.sound);
    }
    if (opts.badgeNumber > 0) {
        request.SetBadgeNumber(opts.badgeNumber);
    }
    if (opts.autoDeletedTime >= 0) {
        request.SetAutoDeletedTime(opts.autoDeletedTime);
    }
    if (!opts.label.empty()) {
        request.SetLabel(TruncateString(opts.label, MAX_LABEL_LEN));
    }
    if (!opts.groupName.empty()) {
        request.SetGroupName(TruncateString(opts.groupName, MAX_LABEL_LEN));
    }
}

ErrCode NotificationShellCommand::RunAsPublishCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "发布通知", "", "", resultReceiver_);
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    PublishOptions opts;
    ErrCode ret = ParsePublishOptions(opts);
    if (ret != ERR_OK) {
        return ret;
    }
    if (opts.helpRequested) {
        return ERR_OK;
    }

    ret = ValidatePublishRequiredOptions(opts);
    if (ret != ERR_OK) {
        return ret;
    }

    NotificationRequest request(opts.notificationId);

    ret = ApplyPublishOptions(opts, request);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = NotificationHelper::PublishNotification(request);
    if (ret == ERR_OK) {
        json data;
        OutputSuccess(data, resultReceiver_);
        return ERR_OK;
    }
    OutputApiError(ret, "发布通知",
        "示例: ohos-notificationManager publish --notificationId 1 "
        "--notificationContent \"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"Test\\\",\\\"text\\\":\\\"Hello\\\"}\"",
        "", resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::BuildNotificationContent(const std::string &contentJson,
    NotificationRequest &request)
{
    if (!json::accept(contentJson)) {
        OutputError("ERR_ARG_INVALID", "通知内容JSON解析失败: JSON格式无效",
            "请提供有效的JSON格式。示例: --notificationContent "
            "\"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"T\\\",\\\"text\\\":\\\"X\\\"}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    json contentObj = json::parse(contentJson, nullptr, false);
    if (contentObj.is_discarded() || !contentObj.is_object()) {
        OutputError("ERR_ARG_INVALID", "通知内容JSON解析失败: JSON不是有效对象",
            "请提供有效的JSON对象。示例: --notificationContent "
            "\"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"T\\\",\\\"text\\\":\\\"X\\\"}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }

    std::string contentType;
    if (contentObj.contains("type") && contentObj["type"].is_string()) {
        contentType = contentObj["type"].get<std::string>();
    }
    if (contentType.empty()) {
        OutputError("ERR_ARG_MISSING", "通知内容中 type 不能为空",
            "请在 --notificationContent JSON中包含 type 字段（basic/long_text/multiline）", resultReceiver_);
        return ERR_INVALID_VALUE;
    }

    std::string cTitle;
    if (contentObj.contains("title") && contentObj["title"].is_string()) {
        cTitle = TruncateString(contentObj["title"].get<std::string>(), MAX_TITLE_LEN);
    }
    if (cTitle.empty()) {
        OutputError("ERR_ARG_INVALID", "通知内容中 title 不能为空",
            "请在 --notificationContent JSON中包含 title 字段", resultReceiver_);
        return ERR_INVALID_VALUE;
    }

    std::string cText;
    if (contentObj.contains("text") && contentObj["text"].is_string()) {
        cText = TruncateString(contentObj["text"].get<std::string>(), MAX_CONTENT_TEXT_LEN);
    }
    if (cText.empty()) {
        OutputError("ERR_ARG_INVALID", "通知内容中 text 不能为空",
            "请在 --notificationContent JSON中包含 text 字段", resultReceiver_);
        return ERR_INVALID_VALUE;
    }

    std::string cAdditionalText;
    if (contentObj.contains("additionalText") && contentObj["additionalText"].is_string()) {
        cAdditionalText = TruncateString(contentObj["additionalText"].get<std::string>(), MAX_CONTENT_TEXT_LEN);
    }
    
    if (contentType == "basic") {
        BuildBasicContent(cTitle, cText, cAdditionalText, request);
        return ERR_OK;
    }
    if (contentType == "long_text") {
        return BuildLongTextContent(contentObj, cTitle, cText, cAdditionalText, request);
    }
    if (contentType == "multiline") {
        return BuildMultilineContent(contentObj, cTitle, cText, cAdditionalText, request);
    }
    OutputError("ERR_ARG_INVALID",
        "通知内容类型 " + contentType + " 不支持: 仅支持 basic、long_text、multiline",
        "请使用有效的内容类型。示例: --notificationContent "
        "\"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"T\\\",\\\"text\\\":\\\"X\\\"}\"",
        resultReceiver_);
    return ERR_INVALID_VALUE;
}

void NotificationShellCommand::BuildBasicContent(const std::string &cTitle,
    const std::string &cText, const std::string &cAdditionalText, NotificationRequest &request)
{
    auto normalContent = std::make_shared<NotificationNormalContent>();
    normalContent->SetTitle(cTitle);
    normalContent->SetText(cText);
    normalContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::BASIC_TEXT));
    if (!cAdditionalText.empty()) {
        normalContent->SetAdditionalText(cAdditionalText);
    }
    auto content = std::make_shared<NotificationContent>(normalContent);
    request.SetContent(content);
}

ErrCode NotificationShellCommand::BuildLongTextContent(const json &contentObj,
    const std::string &cTitle, const std::string &cText,
    const std::string &cAdditionalText, NotificationRequest &request)
{
    if (!contentObj.contains("longText") || !contentObj["longText"].is_string()
        || contentObj["longText"].get<std::string>().empty()) {
        OutputError("ERR_ARG_INVALID", "long_text类型通知内容中 longText 不能为空",
            "请在 --notificationContent JSON中包含 longText 字段", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (!contentObj.contains("briefText") || !contentObj["briefText"].is_string()
        || contentObj["briefText"].get<std::string>().empty()) {
        OutputError("ERR_ARG_INVALID", "long_text类型通知内容中 briefText 不能为空",
            "请在 --notificationContent JSON中包含 briefText 字段", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (!contentObj.contains("expandedTitle") || !contentObj["expandedTitle"].is_string()
        || contentObj["expandedTitle"].get<std::string>().empty()) {
        OutputError("ERR_ARG_INVALID", "long_text类型通知内容中 expandedTitle 不能为空",
            "请在 --notificationContent JSON中包含 expandedTitle 字段", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    std::string longText = TruncateString(contentObj["longText"].get<std::string>(), MAX_CONTENT_TEXT_LEN);
    std::string expandedTitle = TruncateString(contentObj["expandedTitle"].get<std::string>(), MAX_TITLE_LEN);
    std::string briefText = TruncateString(contentObj["briefText"].get<std::string>(), MAX_TITLE_LEN);

    auto longContent = std::make_shared<NotificationLongTextContent>();
    longContent->SetTitle(cTitle);
    longContent->SetText(cText);
    longContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::LONG_TEXT));
    longContent->SetLongText(longText);
    longContent->SetExpandedTitle(expandedTitle);
    longContent->SetBriefText(briefText);
    if (!cAdditionalText.empty()) {
        longContent->SetAdditionalText(cAdditionalText);
    }
    request.SetContent(std::make_shared<NotificationContent>(longContent));
    return ERR_OK;
}

ErrCode NotificationShellCommand::BuildMultilineContent(const json &contentObj,
    const std::string &cTitle, const std::string &cText,
    const std::string &cAdditionalText, NotificationRequest &request)
{
    if (!contentObj.contains("briefText") || !contentObj["briefText"].is_string()
        || contentObj["briefText"].get<std::string>().empty()) {
        OutputError("ERR_ARG_INVALID", "multiline类型通知内容中 briefText 不能为空",
            "请在 --notificationContent JSON中包含 briefText 字段", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (!contentObj.contains("expandedTitle") || !contentObj["expandedTitle"].is_string()
        || contentObj["expandedTitle"].get<std::string>().empty()) {
        OutputError("ERR_ARG_INVALID", "multiline类型通知内容中 expandedTitle 不能为空",
            "请在 --notificationContent JSON中包含 expandedTitle 字段", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (!contentObj.contains("lines") || !contentObj["lines"].is_array()
        || contentObj["lines"].empty()) {
        OutputError("ERR_ARG_INVALID", "multiline类型通知内容中 lines 不能为空",
            "请在 --notificationContent JSON中包含 lines 字段（数组，最多3行）", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    std::string expandedTitle = TruncateString(contentObj["expandedTitle"].get<std::string>(), MAX_TITLE_LEN);
    std::string briefText = TruncateString(contentObj["briefText"].get<std::string>(), MAX_TITLE_LEN);

    auto multiContent = std::make_shared<NotificationMultiLineContent>();
    multiContent->SetTitle(cTitle);
    multiContent->SetText(cText);
    multiContent->SetContentType(static_cast<int32_t>(NotificationContent::Type::MULTILINE));
    multiContent->SetExpandedTitle(expandedTitle);
    multiContent->SetBriefText(briefText);
    if (!cAdditionalText.empty()) {
        multiContent->SetAdditionalText(cAdditionalText);
    }
    int lineCount = 0;
    for (const auto &line : contentObj["lines"]) {
        if (line.is_string() && lineCount < 3) {
            multiContent->AddSingleLine(TruncateString(line.get<std::string>(), MAX_TITLE_LEN));
            lineCount++;
        }
    }
    request.SetContent(std::make_shared<NotificationContent>(multiContent));
    return ERR_OK;
}

ErrCode NotificationShellCommand::ApplyPublishOptions(const PublishOptions &opts,
    NotificationRequest &request)
{
    request.SetSlotType(static_cast<NotificationConstant::SlotType>(opts.slotType));
    ApplySimplePublishFields(opts, request);

    ErrCode ret = BuildNotificationContent(opts.contentJson, request);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = ParseAndApplyNotificationFlags(opts.flagsStr, request);
    if (ret != ERR_OK) {
        return ret;
    }
    return ERR_OK;
}

ErrCode NotificationShellCommand::ParseAndApplyNotificationFlags(const std::string &jsonStr,
    NotificationRequest &request)
{
    if (jsonStr.empty()) {
        return ERR_OK;
    }
    if (!json::accept(jsonStr)) {
        OutputError("ERR_ARG_INVALID", "通知标志JSON解析失败: JSON格式无效",
            "请提供有效的JSON格式。示例: --notificationFlags \"{\\\"soundEnabled\\\":2,\\\"vibrationEnabled\\\":2}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    json flagsObj = json::parse(jsonStr);
    if (!flagsObj.is_object()) {
        OutputError("ERR_ARG_INVALID", "通知标志必须是JSON对象",
            "请提供JSON对象格式。示例: --notificationFlags \"{\\\"soundEnabled\\\":2}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    auto notificationFlags = std::make_shared<NotificationFlags>();
    for (auto it = flagsObj.begin(); it != flagsObj.end(); ++it) {
        if (!it.value().is_number() || it.value().get<int>() != 2) {
            OutputError("ERR_ARG_INVALID", "通知标志字段 " + it.key() + " 的值仅支持2（关闭）",
                "请将标志值设为2。示例: --notificationFlags \"{\\\"soundEnabled\\\":2}\"",
                resultReceiver_);
            return ERR_INVALID_VALUE;
        }
        if (it.key() == "soundEnabled") {
            notificationFlags->SetSoundEnabled(NotificationConstant::FlagStatus::CLOSE);
        } else if (it.key() == "vibrationEnabled") {
            notificationFlags->SetVibrationEnabled(NotificationConstant::FlagStatus::CLOSE);
        } else if (it.key() == "bannerEnabled") {
            notificationFlags->SetBannerEnabled(NotificationConstant::FlagStatus::CLOSE);
        } else if (it.key() == "lockScreenEnabled") {
            notificationFlags->SetLockScreenEnabled(NotificationConstant::FlagStatus::CLOSE);
        }
    }
    request.SetFlags(notificationFlags);
    return ERR_OK;
}

ErrCode NotificationShellCommand::RunAsCancelByIdCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "取消通知", "", PERM_CONTROLLER_AND_AGENT, resultReceiver_);
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    std::string bundleOptionStr;
    int32_t notificationId = 0;
    bool hasNotificationId = false;
    optind = 0;
    int option = getopt_long(argc_, argv_, SHORT_OPTIONS_CANCEL_BY_ID, LONG_OPTIONS_CANCEL_BY_ID, nullptr);
    while (option != -1) {
        switch (option) {
            case 'h':
                resultReceiver_.append(CANCEL_BY_ID_HELP_MSG);
                return ERR_OK;
            case 'o':
                bundleOptionStr = optarg;
                break;
            case 'i': {
                hasNotificationId = true;
                char *endPtr = nullptr;
                long idVal = strtol(optarg, &endPtr, 10);
                if (endPtr == optarg || *endPtr != '\0') {
                    OutputError("ERR_ARG_INVALID", "notificationId参数值无效: 必须为有效整数",
                        "请使用有效的整数。示例: --notificationId 1", resultReceiver_);
                    return ERR_INVALID_VALUE;
                }
                notificationId = static_cast<int32_t>(idVal);
                break;
            }
            default:
                OutputError("ERR_UNKNOWN_OPTION", "未知选项: cancelById命令不支持该选项",
                    "请使用 --help 查看可用选项。示例: ohos-notificationManager cancelById --help",
                    resultReceiver_);
                return ERR_INVALID_VALUE;
        }
        option = getopt_long(argc_, argv_, SHORT_OPTIONS_CANCEL_BY_ID, LONG_OPTIONS_CANCEL_BY_ID, nullptr);
    }

    NotificationBundleOption bundleOption;
    ErrCode ret = ParseBundleOption(bundleOptionStr, bundleOption);
    if (ret != ERR_OK) {
        return ret;
    }

    if (!hasNotificationId) {
        OutputError("ERR_ARG_MISSING", "通知ID（--notificationId）缺失: 必须提供有效的通知ID",
            "请提供通知ID参数。示例: ohos-notificationManager cancelById "
            "--bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --notificationId 1",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }

    ret = NotificationHelper::CancelAsBundle(bundleOption, notificationId);
    if (ret == ERR_OK) {
        json data;
        OutputSuccess(data, resultReceiver_);
        return ERR_OK;
    }
    OutputApiError(ret, "取消通知",
        "示例: ohos-notificationManager cancelById "
        "--bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --notificationId 1",
        PERM_CONTROLLER_AND_AGENT, resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::ParseHashcodes(const std::string &jsonStr,
    std::vector<std::string> &hashcodes)
{
    if (jsonStr.empty()) {
        OutputError("ERR_ARG_MISSING", "hashcodes缺失或为空: 必须提供至少一个通知哈希码",
            "请提供通知哈希码参数。示例: ohos-notificationManager remove "
            "--hashcodes \"[\\\"hash1\\\",\\\"hash2\\\"]\"", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (!json::accept(jsonStr)) {
        OutputError("ERR_ARG_INVALID", "hashcodes参数解析失败: JSON格式无效",
            "请提供有效的JSON数组字符串。示例: --hashcodes \"[\\\"hash1\\\",\\\"hash2\\\"]\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    auto hashcodesJson = json::parse(jsonStr);
    if (!hashcodesJson.is_array() || hashcodesJson.empty()) {
        OutputError("ERR_ARG_MISSING", "hashcodes缺失或为空: 必须提供至少一个通知哈希码",
            "请提供通知哈希码参数。示例: ohos-notificationManager remove "
            "--hashcodes \"[\\\"hash1\\\",\\\"hash2\\\"]\"", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    for (const auto &item : hashcodesJson) {
        if (item.is_string()) {
            hashcodes.push_back(item.get<std::string>());
        }
    }
    if (hashcodes.empty()) {
        OutputError("ERR_ARG_MISSING", "hashcodes缺失或为空: 必须提供至少一个通知哈希码",
            "请提供通知哈希码参数。示例: --hashcodes \"[\\\"hash1\\\"]\"", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    return ERR_OK;
}

ErrCode NotificationShellCommand::RunAsBatchCancelCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "批量取消通知", "", PERM_CONTROLLER, resultReceiver_);
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    std::string hashcodesStr;
    optind = 0;
    int option = getopt_long(argc_, argv_, SHORT_OPTIONS_BATCH_CANCEL, LONG_OPTIONS_BATCH_CANCEL, nullptr);
    while (option != -1) {
        switch (option) {
            case 'h':
                resultReceiver_.append(BATCH_CANCEL_HELP_MSG);
                return ERR_OK;
            case 'a':
                hashcodesStr = optarg;
                break;
            default:
                OutputError("ERR_UNKNOWN_OPTION", "未知选项: batchCancel命令不支持该选项",
                    "请使用 --help 查看可用选项。示例: ohos-notificationManager batchCancel --help",
                    resultReceiver_);
                return ERR_INVALID_VALUE;
        }
        option = getopt_long(argc_, argv_, SHORT_OPTIONS_BATCH_CANCEL, LONG_OPTIONS_BATCH_CANCEL, nullptr);
    }

    std::vector<std::string> hashcodes;
    ErrCode ret = ParseHashcodes(hashcodesStr, hashcodes);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = NotificationHelper::RemoveNotifications(hashcodes, NotificationConstant::SHELL_REASON_DELETE);
    if (ret == ERR_OK) {
        json data;
        OutputSuccess(data, resultReceiver_);
        return ERR_OK;
    }
    OutputApiError(ret, "批量取消通知",
        "示例: ohos-notificationManager batchCancel --hashcodes \"[\\\"hash1\\\"]\"",
        PERM_CONTROLLER, resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::RunAsCancelByBundleCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "取消通知", "", PERM_CONTROLLER, resultReceiver_);
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    std::string bundleOptionStr;

    optind = 0;
    int option = getopt_long(argc_, argv_, SHORT_OPTIONS_CANCEL_BY_BUNDLE, LONG_OPTIONS_CANCEL_BY_BUNDLE, nullptr);
    while (option != -1) {
        switch (option) {
            case 'h':
                resultReceiver_.append(CANCEL_BY_BUNDLE_HELP_MSG);
                return ERR_OK;
            case 'o':
                bundleOptionStr = optarg;
                break;
            default:
                OutputError("ERR_UNKNOWN_OPTION", "未知选项: cancelByBundle命令不支持该选项",
                    "请使用 --help 查看可用选项。示例: ohos-notificationManager cancelByBundle --help",
                    resultReceiver_);
                return ERR_INVALID_VALUE;
        }
        option = getopt_long(argc_, argv_, SHORT_OPTIONS_CANCEL_BY_BUNDLE, LONG_OPTIONS_CANCEL_BY_BUNDLE, nullptr);
    }

    NotificationBundleOption bundleOption;
    ErrCode ret = ParseBundleOption(bundleOptionStr, bundleOption);
    if (ret != ERR_OK) {
        return ret;
    }

    ret = NotificationHelper::RemoveNotificationsByBundle(bundleOption);
    if (ret == ERR_OK) {
        json data;
        OutputSuccess(data, resultReceiver_);
        return ERR_OK;
    }
    OutputApiError(ret, "取消通知",
        "示例: ohos-notificationManager cancelByBundle "
        "--bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"",
        PERM_CONTROLLER, resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::RunAsEnableNotificationCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "设置通知开关", "", PERM_CONTROLLER, resultReceiver_);
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    std::string bundleOptionStr;
    bool enabled = false;
    optind = 0;
    int option = getopt_long(argc_, argv_,
        SHORT_OPTIONS_ENABLE_NOTIFICATION, LONG_OPTIONS_ENABLE_NOTIFICATION, nullptr);
    while (option != -1) {
        switch (option) {
            case 'h':
                resultReceiver_.append(ENABLE_NOTIFICATION_HELP_MSG);
                return ERR_OK;
            case 'o':
                bundleOptionStr = optarg;
                break;
            case 'e':
                enabled = true;
                break;
            default:
                OutputError("ERR_UNKNOWN_OPTION", "未知选项: enableNotification命令不支持该选项",
                    "请使用 --help 查看可用选项。示例: ohos-notificationManager enableNotification --help",
                    resultReceiver_);
                return ERR_INVALID_VALUE;
        }
        option = getopt_long(argc_, argv_,
            SHORT_OPTIONS_ENABLE_NOTIFICATION, LONG_OPTIONS_ENABLE_NOTIFICATION, nullptr);
    }
    NotificationBundleOption bundleOption;
    ErrCode ret = ParseBundleOption(bundleOptionStr, bundleOption);
    if (ret != ERR_OK) {
        return ret;
    }
    std::string deviceId {""};
    ret = NotificationHelper::SetNotificationsEnabledForSpecifiedBundle(bundleOption, deviceId, enabled);
    if (ret == ERR_OK) {
        json data;
        OutputSuccess(data, resultReceiver_);
        return ERR_OK;
    }
    OutputApiError(ret, "设置通知开关",
        "示例: ohos-notificationManager enableNotification "
        "--bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --enabled true",
        PERM_CONTROLLER, resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::RunAsSetSlotFlagsCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "设置渠道标志", "", PERM_CONTROLLER, resultReceiver_);
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }
    std::string bundleOptionStr;
    uint32_t slotFlags = 0;
    bool hasFlags = false;
    optind = 0;
    int option = getopt_long(argc_, argv_, SHORT_OPTIONS_SET_SLOT_FLAGS, LONG_OPTIONS_SET_SLOT_FLAGS, nullptr);
    while (option != -1) {
        switch (option) {
            case 'h':
                resultReceiver_.append(SET_SLOT_FLAGS_HELP_MSG);
                return ERR_OK;
            case 'o': bundleOptionStr = optarg; break;
            case 'f':
                hasFlags = true;
                slotFlags = (optarg != nullptr && strncmp(optarg, "0x", 2) == 0)
                    ? static_cast<uint32_t>(strtoul(optarg, nullptr, 16))
                    : static_cast<uint32_t>(atoi(optarg));
                break;
            default:
                OutputError("ERR_UNKNOWN_OPTION", "未知选项: setSlotFlags命令不支持该选项",
                    "请使用 --help 查看可用选项。示例: ohos-notificationManager setSlotFlags --help",
                    resultReceiver_);
                return ERR_INVALID_VALUE;
        }
        option = getopt_long(argc_, argv_, SHORT_OPTIONS_SET_SLOT_FLAGS, LONG_OPTIONS_SET_SLOT_FLAGS, nullptr);
    }
    NotificationBundleOption bundleOption;
    ErrCode ret = ParseBundleOption(bundleOptionStr, bundleOption);
    if (ret != ERR_OK) {
        return ret;
    }
    if (!hasFlags) {
        OutputError("ERR_ARG_MISSING", "渠道标志（--flags）缺失: 必须提供渠道标志位掩码",
            "请提供渠道标志参数。示例: ohos-notificationManager setSlotFlags "
            "--bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --flags 1",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (slotFlags < 0 || slotFlags > MAX_SLOT_FLAGS) {
        OutputError("ERR_ARG_INVALID", "渠道标志值无效: 不能小于0或者大于63(0b111111)",
            "请使用有效的渠道标志值（0-63）。示例: --flags 63", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    ret = NotificationHelper::SetNotificationSlotFlagsAsBundle(bundleOption, slotFlags);
    if (ret == ERR_OK) {
        json data;
        OutputSuccess(data, resultReceiver_);
        return ERR_OK;
    }
    OutputApiError(ret, "设置渠道标志",
        "示例: ohos-notificationManager setSlotFlags "
        "--bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --flags 63",
        PERM_CONTROLLER, resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::RunAsListAllNotificationCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "查询通知", "", PERM_CONTROLLER, resultReceiver_);
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    optind = 0;
    int option = getopt_long(argc_, argv_, SHORT_OPTIONS_LIST_ALL_NOTIFICATION,
        LONG_OPTIONS_LIST_ALL_NOTIFICATION, nullptr);
    if (option == 'h') {
        resultReceiver_.append(LIST_ALL_NOTIFICATION_HELP_MSG);
        return ERR_OK;
    }
    if (option == '?') {
        OutputError("ERR_UNKNOWN_OPTION", "未知选项: list命令不支持额外选项",
            "请使用 --help 查看可用选项。示例: ohos-notificationManager listAllNotification --help",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }

    std::vector<sptr<Notification>> notifications;
    ErrCode ret = NotificationHelper::GetAllActiveNotifications(notifications);
    if (ret != ERR_OK) {
        OutputApiError(ret, "查询活跃通知",
            "示例: ohos-notificationManager listAllNotification", PERM_CONTROLLER, resultReceiver_);
        return ret;
    }

    json notificationList = json::array();
    for (const auto &notif : notifications) {
        if (notif == nullptr) {
            continue;
        }
        json item;
        SerializeNotification(notif, item);
        notificationList.push_back(item);
    }
    json data;
    data["notifications"] = notificationList;
    data["total"] = notificationList.size();
    OutputSuccess(data, resultReceiver_);
    return ERR_OK;
}

void NotificationShellCommand::SerializeNotification(const sptr<Notification> &notif, json &item)
{
    auto request = notif->GetNotificationRequestPoint();
    if (request == nullptr) {
        return;
    }
    item["notificationId"] = request->GetNotificationId();
    item["createTime"] = request->GetCreateTime();
    item["ownerUid"] = request->GetOwnerUid();
    item["ownerUserId"] = request->GetOwnerUserId();
    item["ownerBundleName"] = request->GetOwnerBundleName();
    item["label"] = request->GetLabel();
    item["appInstanceKey"] = request->GetAppInstanceKey();
    item["slotType"] = static_cast<int32_t>(request->GetSlotType());
    auto content = request->GetContent();
    if (content != nullptr) {
        json contentObj;
        SerializeNotificationContent(content, contentObj);
        item["notificationContent"] = contentObj;
    }
    auto actionButtons = request->GetActionButtons();
    if (!actionButtons.empty()) {
        json btnArray = json::array();
        for (const auto &btn : actionButtons) {
            if (btn != nullptr) {
                btnArray.push_back(json{{"title", btn->GetTitle()}});
            }
        }
        item["actionButtons"] = btnArray;
    }
    auto flags = request->GetFlags();
    if (flags != nullptr) {
        json flagsObj;
        flagsObj["soundEnabled"] = static_cast<int32_t>(flags->IsSoundEnabled());
        flagsObj["vibrationEnabled"] = static_cast<int32_t>(flags->IsVibrationEnabled());
        flagsObj["bannerEnabled"] = static_cast<int32_t>(flags->IsBannerEnabled());
        flagsObj["lockScreenEnabled"] = static_cast<int32_t>(flags->IsLockScreenEnabled());
        item["notificationFlags"] = flagsObj;
    }
    item["hashCode"] = request->GetBaseKey("");
}

void NotificationShellCommand::SerializeNotificationContent(
    const std::shared_ptr<NotificationContent> &content, json &contentObj)
{
    auto contentType = content->GetContentType();
    auto baseContent = content->GetNotificationContent();
    switch (contentType) {
        case NotificationContent::Type::BASIC_TEXT: contentObj["type"] = "basic"; break;
        case NotificationContent::Type::LONG_TEXT: contentObj["type"] = "long_text"; break;
        case NotificationContent::Type::MULTILINE: contentObj["type"] = "multiline"; break;
        case NotificationContent::Type::PICTURE: contentObj["type"] = "picture"; break;
        case NotificationContent::Type::CONVERSATION: contentObj["type"] = "conversation"; break;
        case NotificationContent::Type::MEDIA: contentObj["type"] = "media"; break;
        case NotificationContent::Type::LIVE_VIEW: contentObj["type"] = "live_view"; break;
        case NotificationContent::Type::LOCAL_LIVE_VIEW: contentObj["type"] = "local_live_view"; break;
        default: contentObj["type"] = "unknown"; break;
    }
    if (baseContent != nullptr) {
        SerializeBasicContent(baseContent, contentObj);
    }
    if (contentType == NotificationContent::Type::LONG_TEXT) {
        SerializeLongTextContent(baseContent, contentObj);
    } else if (contentType == NotificationContent::Type::MULTILINE) {
        SerializeMultilineContent(baseContent, contentObj);
    } else if (contentType == NotificationContent::Type::PICTURE) {
        SerializePictureContent(baseContent, contentObj);
    } else if (contentType == NotificationContent::Type::CONVERSATION) {
        SerializeConversationContent(baseContent, contentObj);
    } else if (contentType == NotificationContent::Type::MEDIA) {
        SerializeMediaContent(baseContent, contentObj);
    } else if (contentType == NotificationContent::Type::LIVE_VIEW) {
        SerializeLiveViewContent(baseContent, contentObj);
    } else if (contentType == NotificationContent::Type::LOCAL_LIVE_VIEW) {
        SerializeLocalLiveViewContent(baseContent, contentObj);
    }
}

void NotificationShellCommand::SerializeBasicContent(
    const std::shared_ptr<NotificationBasicContent> &baseContent, json &contentObj)
{
    contentObj["title"] = baseContent->GetTitle();
    contentObj["text"] = baseContent->GetText();
    if (!baseContent->GetAdditionalText().empty()) {
        contentObj["additionalText"] = baseContent->GetAdditionalText();
    }
}

void NotificationShellCommand::SerializeLongTextContent(
    const std::shared_ptr<NotificationBasicContent> &baseContent, json &contentObj)
{
    auto longContent = std::static_pointer_cast<NotificationLongTextContent>(baseContent);
    if (longContent != nullptr) {
        contentObj["longText"] = longContent->GetLongText();
        contentObj["expandedTitle"] = longContent->GetExpandedTitle();
        contentObj["briefText"] = longContent->GetBriefText();
    }
}

void NotificationShellCommand::SerializeMultilineContent(
    const std::shared_ptr<NotificationBasicContent> &baseContent, json &contentObj)
{
    auto multiContent = std::static_pointer_cast<NotificationMultiLineContent>(baseContent);
    if (multiContent != nullptr) {
        contentObj["expandedTitle"] = multiContent->GetExpandedTitle();
        contentObj["briefText"] = multiContent->GetBriefText();
        contentObj["lines"] = multiContent->GetAllLines();
    }
}

void NotificationShellCommand::SerializePictureContent(
    const std::shared_ptr<NotificationBasicContent> &baseContent, json &contentObj)
{
    auto picContent = std::static_pointer_cast<NotificationPictureContent>(baseContent);
    if (picContent != nullptr) {
        contentObj["expandedTitle"] = picContent->GetExpandedTitle();
        contentObj["briefText"] = picContent->GetBriefText();
    }
}

void NotificationShellCommand::SerializeConversationContent(
    const std::shared_ptr<NotificationBasicContent> &baseContent, json &contentObj)
{
    auto convContent = std::static_pointer_cast<NotificationConversationalContent>(baseContent);
    if (convContent != nullptr) {
        contentObj["conversationTitle"] = convContent->GetConversationTitle();
        contentObj["isGroup"] = convContent->IsConversationGroup();
        json messages = json::array();
        for (const auto &msg : convContent->GetAllConversationalMessages()) {
            if (msg == nullptr) {
                continue;
            }
            json msgObj;
            msgObj["text"] = msg->GetText();
            msgObj["arrivedTime"] = msg->GetArrivedTime();
            auto sender = msg->GetSender();
            msgObj["senderName"] = sender.GetName();
            msgObj["senderKey"] = sender.GetKey();
            messages.push_back(msgObj);
        }
        contentObj["messages"] = messages;
    }
}

void NotificationShellCommand::SerializeMediaContent(
    const std::shared_ptr<NotificationBasicContent> &baseContent, json &contentObj)
{
    auto mediaContent = std::static_pointer_cast<NotificationMediaContent>(baseContent);
    if (mediaContent != nullptr) {
        contentObj["shownActions"] = mediaContent->GetShownActions();
    }
}

void NotificationShellCommand::SerializeLiveViewContent(
    const std::shared_ptr<NotificationBasicContent> &baseContent, json &contentObj)
{
    auto liveContent = std::static_pointer_cast<NotificationLiveViewContent>(baseContent);
    if (liveContent != nullptr) {
        contentObj["liveViewStatus"] = static_cast<int32_t>(liveContent->GetLiveViewStatus());
        contentObj["version"] = liveContent->GetVersion();
    }
}

void NotificationShellCommand::SerializeLocalLiveViewContent(
    const std::shared_ptr<NotificationBasicContent> &baseContent, json &contentObj)
{
    auto localLiveContent = std::static_pointer_cast<NotificationLocalLiveViewContent>(baseContent);
    if (localLiveContent != nullptr) {
        contentObj["liveViewType"] = static_cast<int32_t>(localLiveContent->GetLiveViewType());
    }
}

}  // namespace Notification
}  // namespace OHOS
