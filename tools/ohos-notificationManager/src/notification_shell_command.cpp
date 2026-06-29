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
#include "notification_template.h"
#include "notification_constant.h"
#include "notification_helper.h"
#include "want_params.h"
#include "want_params_wrapper.h"
#include "token_setproc.h"
#include "singleton.h"

using json = nlohmann::json;

namespace OHOS {
namespace Notification {
namespace {
constexpr size_t MAX_LABEL_LEN = 204;
constexpr size_t MAX_TITLE_LEN = 1024;
constexpr size_t MAX_CONTENT_TEXT_LEN = 3072;

std::string TruncateString(const std::string &str, size_t maxLen)
{
    return str.size() > maxLen ? str.substr(0, maxLen) : str;
}

ErrCode ParseEnabledValue(const char *optarg, bool &enabled, std::string &out)
{
    if (optarg == nullptr) {
        return ERR_OK;
    }
    if (strcmp(optarg, "true") == 0 || strcmp(optarg, "1") == 0) {
        enabled = true;
        return ERR_OK;
    }
    if (strcmp(optarg, "false") == 0 || strcmp(optarg, "0") == 0) {
        return ERR_OK;
    }
    OutputError("ERR_ARG_INVALID", "enabled参数值无效: 必须为 true/false",
        "请使用true或false。示例: --enabled true", out);
    return ERR_INVALID_VALUE;
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
    {"tapDismissed", no_argument, nullptr, 12},
    {"autoDeletedTime", required_argument, nullptr, 13},
    {"additionalParams", required_argument, nullptr, 14},
    {"inProgress", no_argument, nullptr, 15},
    {"unRemovable", no_argument, nullptr, 16},
    {"actionButtons", required_argument, nullptr, 17},
    {"notificationFlags", required_argument, nullptr, 18},
    {"notificationTemplate", required_argument, nullptr, 19},
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
    "ohos-notificationManager - OpenHarmony notification management tool. Used for notification publishing, "
    "cancellation, removal, and querying active notifications. Does not support notification subscription or "
    "interactive UI operations.\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager <command> [options]\n"
    "\n"
    "Parameters:\n"
    "  --help                  Display this help message\n"
    "\n"
    "SubCommands:\n"
    "  help                    Show help message\n"
    "  publish                 Publish a notification to the system\n"
    "  cancelById              Cancel notification by bundle and notification ID\n"
    "  cancelByBundle          Cancel all notifications for a specified bundle\n"
    "  batchCancel             Batch cancel notifications by hashcodes\n"
    "  enableNotification      Set notification enabled/disabled for bundle\n"
    "  setSlotFlags            Set notification slot flags for bundle\n"
    "  listAllNotification     List all active notifications\n"
    "\n"
    "Examples:\n"
    "  ohos-notificationManager --help\n"
    "  ohos-notificationManager publish --help\n";

constexpr char PUBLISH_HELP_MSG[] =
    "ohos-notificationManager publish - Publish a notification. "
    "Used for sending notifications to the system. Does not support subscription-type notifications.\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager publish --notificationContent <json> [options]\n"
    "\n"
    "Parameters:\n"
    "  --notificationContent <json>     Notification content as JSON string (required, max 4096 bytes)\n"
    "                               Supported types: basic, long_text, multiline\n"
    "                               All types require: title(≤1024B), text(≤3072B)\n"
    "                               All types optional: additionalText(≤3072B)\n"
    "                               All limits are bytes, overlength truncated\n"
    "                               basic: {\"type\":\"basic\",\"title\":\"T\",\"text\":\"X\",\n"
    "                                        \"additionalText\":\"A\"}\n"
    "                               long_text: {\"type\":\"long_text\",\"title\":\"T\",\"text\":\"X\",\n"
    "                                           \"longText\":\"L\",\"expandedTitle\":\"E\",\n"
    "                                           \"briefText\":\"B\",\"additionalText\":\"A\"}\n"
    "                                 Required: longText(≤3072B), expandedTitle(≤1024B), briefText(≤1024B)\n"
    "                               multiline: {\"type\":\"multiline\",\"title\":\"T\",\"text\":\"X\",\n"
    "                                            \"expandedTitle\":\"E\",\"briefText\":\"B\",\n"
    "                                            \"lines\":[\"line1\",\"line2\"],\n"
    "                                            \"additionalText\":\"A\"}\n"
    "                                 Required: expandedTitle(≤1024B), briefText(≤1024B),\n"
    "                                           lines(≤3 lines, ≤1024B/line)\n"
    "  --notificationId <id>            Notification ID (optional, default: 0, integer ≥ 0)\n"
    "  --slotType <type>                Notification slot type (optional, 0-7 except 5, default: 3)\n"
    "                               0=SOCIAL_COMMUNICATION, 1=SERVICE_REMINDER,\n"
    "                               2=CONTENT_INFORMATION, 3=OTHER, 4=CUSTOM,\n"
    "                               6=CUSTOMER_SERVICE, 7=EMERGENCY_INFORMATION\n"
    "                               Note: slotType 5 (LIVE_VIEW) is not supported\n"
    "  --updateOnly                     Update existing notification only, do not create new (optional, flag)\n"
    "  --appMessageId <id>              Application message ID (optional, string, max 256 bytes)\n"
    "  --priorityNotificationType <type> Priority notification type (optional, string)\n"
    "                               Enum: alarm, call, email, err, event, msg, navigation,\n"
    "                               progress, promo, recommendation, reminder, service,\n"
    "                               social, status, sys, transport\n"
    "  --alertOneTime                   Alert only once, subsequent updates will not alert (optional, flag)\n"
    "  --sound <uri>                    Custom notification sound URI (optional, string, max 204 bytes)\n"
    "  --badgeNumber <number>           Badge number to add to current badge count (optional, integer ≥ 0)\n"
    "  --tapDismissed                   Auto-dismiss on tap (optional, flag)\n"
    "  --autoDeletedTime <ms>           Auto-delete time in milliseconds (optional, integer ≥ 0)\n"
    "  --label <label>                  Notification label (optional, string, max 204 bytes)\n"
    "  --groupName <name>               Notification group name (optional, string, max 204 bytes, overlength truncated)\n"
    "  --additionalParams <str>         Additional data as WantParams serialized string (optional, max 4096 bytes)\n"
    "                               Example: \"{\\\"key1\\\":\\\"val1\\\",\\\"key2\\\":\\\"val2\\\"}\"\n"
    "  --inProgress                     Mark as in-progress notification (optional, flag)\n"
    "  --unRemovable                    Mark as unremovable notification (optional, flag)\n"
    "  --actionButtons <json>           Action buttons as JSON array (optional, max 4096 bytes, title only)\n"
    "                               Example: \"[{\\\"title\\\":\\\"Action1\\\"},{\\\"title\\\":\\\"Action2\\\"}]\"\n"
    "  --notificationFlags <json>       Notification reminder flags as JSON (optional, max 4096 bytes)\n"
    "                               Supported: soundEnabled, vibrationEnabled, bannerEnabled, lockScreenEnabled\n"
    "                               Value must be 2 (CLOSE). Example: \"{\\\"soundEnabled\\\":2,\\\"vibrationEnabled\\\":2}\"\n"
    "  --notificationTemplate <json>    Notification template as JSON (optional, max 4096 bytes)\n"
    "                               Contains name(≤204B, overlength truncated) and optional data(WantParams)\n"
    "                               Example: \"{\\\"name\\\":\\\"downloadTemplate\\\",\\\"data\\\":\\\"{\\\"progress\\\":\\\"50\\\"}\\\"}\"\n"
    "  --help                           Display this help message\n"
    "\n"
    "Examples:\n"
    "  # Publish a basic notification\n"
    "  ohos-notificationManager publish --notificationContent \"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"Test\\\",\\\"text\\\":\\\"Hello\\\"}\"\n"
    "  # Publish with slot type and options\n"
    "  ohos-notificationManager publish --notificationContent \"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"Alert\\\",\\\"text\\\":\\\"Content\\\"}\" --slotType 1\n";

constexpr char CANCEL_BY_ID_HELP_MSG[] =
    "ohos-notificationManager cancelById - Cancel notification by bundle and notification ID. "
    "Used for managing notifications of specific applications. Does not support canceling notifications "
    "without bundle information.\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager cancelById --bundleOption <json> --notificationId <id>\n"
    "\n"
    "Parameters:\n"
    "  --bundleOption <json>  Target bundle option as JSON string (required)\n"
    "                         Contains bundleName(string) and uid(integer)\n"
    "                         Example: \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"\n"
    "  --notificationId <id>  Notification ID to cancel (required, integer)\n"
    "  --help                 Display this help message\n"
    "\n"
    "Examples:\n"
    "  # Cancel a notification by bundle\n"
    "  ohos-notificationManager cancelById --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --notificationId 1\n";

constexpr char BATCH_CANCEL_HELP_MSG[] =
    "ohos-notificationManager batchCancel - Batch cancel notifications by hashcodes. "
    "Used for canceling specific notifications identified by their hashcodes.\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager batchCancel --hashcodes <json>\n"
    "\n"
    "Parameters:\n"
    "  --hashcodes <json>       Notification hashcodes as JSON array string (required)\n"
    "                           Example: [\"hash1\",\"hash2\",\"hash3\"]\n"
    "  --help                   Display this help message\n"
    "\n"
    "Examples:\n"
    "  # Batch cancel specific notifications by hashcodes\n"
    "  ohos-notificationManager batchCancel --hashcodes \"[\\\"hash1\\\",\\\"hash2\\\"]\"\n";

constexpr char CANCEL_BY_BUNDLE_HELP_MSG[] =
    "ohos-notificationManager cancelByBundle - Cancel all notifications for a specified bundle. "
    "Used for batch canceling notifications of a specific application.\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager cancelByBundle --bundleOption <json>\n"
    "\n"
    "Parameters:\n"
    "  --bundleOption <json>  Target bundle option as JSON string (required)\n"
    "                         Contains bundleName(string) and uid(integer)\n"
    "                         Example: \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"\n"
    "  --help                 Display this help message\n"
    "\n"
    "Examples:\n"
    "  # Cancel all notifications for a bundle\n"
    "  ohos-notificationManager cancelByBundle --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"";

constexpr char ENABLE_NOTIFICATION_HELP_MSG[] =
    "ohos-notificationManager enableNotification - Set notification enabled/disabled for a specified bundle. "
    "Used for controlling notification permissions of applications. Does not support setting "
    "notification status without bundle information.\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager enableNotification --bundleOption <json> --enabled <true|false>\n"
    "\n"
    "Parameters:\n"
    "  --bundleOption <json>  Target bundle option as JSON string (required)\n"
    "                         Contains bundleName(string) and uid(integer)\n"
    "                         Example: \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"\n"
    "  --enabled <true|false> Notification enabled status (required, true=enabled, false=disabled)\n"
    "  --help                 Display this help message\n"
    "\n"
    "Examples:\n"
    "  # Enable notifications for a bundle\n"
    "  ohos-notificationManager enableNotification --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --enabled true\n"
    "  # Disable notifications for a bundle\n"
    "  ohos-notificationManager enableNotification --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --enabled false\n";

constexpr char SET_SLOT_FLAGS_HELP_MSG[] =
    "ohos-notificationManager setSlotFlags - Set notification slot flags for a specified bundle. "
    "Used for configuring notification reminder modes of applications. Does not support setting "
    "slot flags without bundle information.\n"
    "\n"
    "Usage:\n"
    "  ohos-notificationManager setSlotFlags --bundleOption <json> --flags <flags>\n"
    "\n"
    "Parameters:\n"
    "  --bundleOption <json>  Target bundle option as JSON string (required)\n"
    "                         Contains bundleName(string) and uid(integer)\n"
    "                         Example: \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"\n"
    "  --flags <flags>        Slot flags bitmask (required, uint32, decimal or hex with 0x prefix)\n"
    "                          Only bit0-bit5 are valid:\n"
    "                          bit0=SOUND, bit1=LOCKSCREEN, bit2=BANNER,\n"
    "                          bit3=LIGHTSCREEN, bit4=VIBRATION, bit5=STATUSBAR_ICON\n"
    "                          Note: LIGHTSCREEN(bit3) and STATUSBAR_ICON(bit5) cannot be turned off\n"
    "  --help                 Display this help message\n"
    "\n"
    "Examples:\n"
    "  # Set all reminder flags\n"
    "  ohos-notificationManager setSlotFlags --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --flags 63\n"
    "  # Set flags with hex format\n"
    "  ohos-notificationManager setSlotFlags --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --flags 0x3F\n";

constexpr char LIST_ALL_NOTIFICATION_HELP_MSG[] =
    "ohos-notificationManager listAllNotification - List all active notifications. "
    "Used for querying current notification status. Does not support listing notifications for other users.\n"
    "\n"
    "Output fields per notification:\n"
    "  notificationId          Notification ID\n"
    "  createTime              Creation timestamp (milliseconds)\n"
    "  ownerUid                Creator UID\n"
    "  ownerUserId             Creator user ID\n"
    "  ownerBundleName         Creator bundle name\n"
    "  label                   Notification label\n"
    "  appInstanceKey          Application instance key\n"
    "  slotType                Slot type (0-7)\n"
    "  additionalParams        Additional key-value parameters\n"
    "  notificationContent     Notification content object (varies by type):\n"
    "                           Common: type, title, text, additionalText(optional)\n"
    "                           basic: only common fields\n"
    "                           long_text: +longText, expandedTitle, briefText\n"
    "                           multiline: +expandedTitle, briefText, lines(array)\n"
    "                           picture: +expandedTitle, briefText\n"
    "                           conversation: +conversationTitle, isGroup, messages(array)\n"
    "                           media: +shownActions(array)\n"
    "                           live_view: +liveViewStatus, version, extraInfo\n"
    "                           local_live_view: +liveViewType\n"
    "  actionButtons           Action button list (title)\n"
    "  notificationFlags       Reminder flags (sound/vibration/banner/lockScreen)\n"
    "  extendInfo              Extended key-value info\n"
    "  hashCode                Notification hash code\n"
    "\n"
    "Parameters:\n"
    "  --help                  Display this help message\n"
    "\n"
    "Examples:\n"
    "  # List all active notifications\n"
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
        ans_ = DelayedSingleton<AnsNotification>::GetInstance();
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
            OutputError("ERR_INVALID_ARG", "bundleOption参数解析失败: JSON格式无效",
                "请提供有效的JSON字符串。示例: --bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\"",
                resultReceiver_);
            return ERR_INVALID_VALUE;
        }
        auto bundleOptionJson = json::parse(jsonStr);
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
            case 12: opts.isTapDismissed = true; break;
            case 13: opts.autoDeletedTime = static_cast<int64_t>(atoll(optarg)); break;
            case 14: opts.additionalParamsJson = optarg; break;
            case 15: opts.isOngoing = true; break;
            case 16: opts.isUnremovable = true; break;
            case 17: opts.actionButtonsJson = optarg; break;
            case 18: opts.flagsStr = optarg; break;
            case 19: opts.templateJson = optarg; break;
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
    if (opts.notificationId < 0) {
        OutputError("ERR_ARG_MISSING", "通知ID（--notificationId）缺失: 必须提供有效的通知ID",
            "请提供通知ID参数。示例: ohos-notificationManager publish --notificationId 1 "
            "--notificationContent \"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"Test\\\",\\\"text\\\":\\\"Hello\\\"}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (opts.contentJson.empty()) {
        OutputError("ERR_ARG_MISSING", "通知内容（--notificationContent）缺失: 必须提供通知内容JSON",
            "请提供通知内容参数。示例: ohos-notificationManager publish --notificationId 1 "
            "--notificationContent \"{\\\"type\\\":\\\"basic\\\",\\\"title\\\":\\\"Test\\\",\\\"text\\\":\\\"Hello\\\"}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (opts.slotType < 0 || opts.slotType > 7 || opts.slotType == 5) {
        OutputError("ERR_ARG_INVALID",
            "渠道类型 " + std::to_string(opts.slotType) + " 无效: 渠道类型必须在 0-7 范围内且不支持 5(LIVE_VIEW)",
            "请使用有效的渠道类型值。示例: --slotType 3（OTHER类型）或 --slotType 4（CUSTOMER_SERVICE类型)",
            resultReceiver_);
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
        request.SetSound(TruncateString(opts.sound, MAX_LABEL_LEN));
    }
    if (opts.badgeNumber > 0) {
        request.SetBadgeNumber(opts.badgeNumber);
    }
    if (opts.isTapDismissed) {
        request.SetTapDismissed(true);
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
    if (opts.isOngoing) {
        request.SetInProgress(true);
    }
    if (opts.isUnremovable) {
        request.SetUnremovable(true);
    }
}

ErrCode NotificationShellCommand::RunAsPublishCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "发布通知", "", resultReceiver_);
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
    request.SetSlotType(static_cast<NotificationConstant::SlotType>(opts.slotType));

    ret = BuildNotificationContent(opts.contentJson, request);
    if (ret != ERR_OK) {
        return ret;
    }

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
        resultReceiver_);
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
    json contentObj = json::parse(contentJson);
    std::string contentType = contentObj.value("type", "basic");
    std::string cTitle = TruncateString(contentObj.value("title", ""), MAX_TITLE_LEN);
    std::string cText = TruncateString(contentObj.value("text", ""), MAX_CONTENT_TEXT_LEN);
    std::string cAdditionalText;
    if (contentObj.contains("additionalText") && contentObj["additionalText"].is_string()) {
        cAdditionalText = TruncateString(contentObj["additionalText"].get<std::string>(), MAX_CONTENT_TEXT_LEN);
    }
    if (cTitle.empty()) {
        OutputError("ERR_ARG_INVALID", "通知内容中 title 不能为空",
            "请在 --notificationContent JSON中包含 title 字段", resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    if (cText.empty()) {
        OutputError("ERR_ARG_INVALID", "通知内容中 text 不能为空",
            "请在 --notificationContent JSON中包含 text 字段", resultReceiver_);
        return ERR_INVALID_VALUE;
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
    ApplySimplePublishFields(opts, request);

    ErrCode ret = ParseAndApplyAdditionalParams(opts.additionalParamsJson, request);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = ParseAndApplyActionButtons(opts.actionButtonsJson, request);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = ParseAndApplyNotificationFlags(opts.flagsStr, request);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = ParseAndApplyNotificationTemplate(opts.templateJson, request);
    if (ret != ERR_OK) {
        return ret;
    }
    return ERR_OK;
}

ErrCode NotificationShellCommand::ParseAndApplyAdditionalParams(const std::string &jsonStr,
    NotificationRequest &request)
{
    if (jsonStr.empty()) {
        return ERR_OK;
    }
    if (!json::accept(jsonStr)) {
        OutputError("ERR_ARG_INVALID", "additionalParams JSON格式无效: 必须为有效的JSON对象字符串",
            "请提供有效的JSON格式。示例: --additionalParams \"{\\\"key1\\\":\\\"val1\\\"}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    AAFwk::WantParams params = AAFwk::WantParamWrapper::ParseWantParams(jsonStr);
    auto wantParams = std::make_shared<AAFwk::WantParams>(params);
    request.SetAdditionalData(wantParams);
    return ERR_OK;
}

ErrCode NotificationShellCommand::ParseAndApplyActionButtons(const std::string &jsonStr,
    NotificationRequest &request)
{
    if (jsonStr.empty()) {
        return ERR_OK;
    }
    if (!json::accept(jsonStr)) {
        OutputError("ERR_ARG_INVALID", "操作按钮JSON解析失败: JSON格式无效",
            "请提供有效的JSON数组格式。示例: --actionButtons \"[{\\\"title\\\":\\\"Action\\\"}]\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    json btnArray = json::parse(jsonStr);
    if (!btnArray.is_array()) {
        OutputError("ERR_ARG_INVALID", "操作按钮必须是JSON数组",
            "请提供JSON数组格式。示例: --actionButtons \"[{\\\"title\\\":\\\"Action\\\"}]\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    for (const auto &btn : btnArray) {
        if (btn.is_object() && btn.contains("title") && btn["title"].is_string()) {
            std::string btnTitle = btn["title"].get<std::string>();
            if (btnTitle.size() > MAX_LABEL_LEN) {
                btnTitle = btnTitle.substr(0, MAX_LABEL_LEN);
            }
            auto actionBtn = NotificationActionButton::Create(nullptr, btnTitle, nullptr, nullptr);
            if (actionBtn != nullptr) {
                request.AddActionButton(actionBtn);
                request.SetIsCoverActionButtons(true);
            }
        }
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

ErrCode NotificationShellCommand::ParseAndApplyNotificationTemplate(const std::string &jsonStr,
    NotificationRequest &request)
{
    if (jsonStr.empty()) {
        return ERR_OK;
    }
    if (!json::accept(jsonStr)) {
        OutputError("ERR_ARG_INVALID", "模板JSON解析失败: JSON格式无效",
            "请提供有效的JSON格式。示例: --notificationTemplate "
            "\"{\\\"name\\\":\\\"downloadTemplate\\\",\\\"data\\\":{\\\"progress\\\":50}}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    json tmplObj = json::parse(jsonStr);
    if (!tmplObj.is_object() || !tmplObj.contains("name") || !tmplObj["name"].is_string()) {
        OutputError("ERR_ARG_INVALID", "模板JSON必须包含 name 字段",
            "请提供包含 name 字段的JSON。示例: --template \"{\\\"name\\\":\\\"downloadTemplate\\\"}\"",
            resultReceiver_);
        return ERR_INVALID_VALUE;
    }
    auto tmpl = std::make_shared<NotificationTemplate>();
    std::string tmplName = tmplObj["name"].get<std::string>();
    if (tmplName.size() > MAX_LABEL_LEN) {
        tmplName = tmplName.substr(0, MAX_LABEL_LEN);
    }
    tmpl->SetTemplateName(tmplName);
    if (tmplObj.contains("data") && tmplObj["data"].is_string()) {
        std::string data = tmplObj["data"].get<std::string>();
        if (!data.empty()) {
            if (!json::accept(data)) {
                OutputError("ERR_ARG_INVALID", "模板data JSON格式无效: 必须为有效的JSON对象字符串",
                    "请提供有效的JSON格式。示例: --notificationTemplate "
                    "\"{\\\"name\\\":\\\"downloadTemplate\\\",\\\"data\\\":\\\"{\\\"progress\\\":\\\"50\\\"}\\\"}\"",
                    resultReceiver_);
                return ERR_INVALID_VALUE;
            }
            AAFwk::WantParams params = AAFwk::WantParamWrapper::ParseWantParams(data);
            tmpl->SetTemplateData(std::make_shared<AAFwk::WantParams>(params));
        }
    }
    request.SetTemplate(tmpl);
    return ERR_OK;
}

ErrCode NotificationShellCommand::RunAsCancelByIdCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "取消通知", "", resultReceiver_);
        return ERR_ANS_SERVICE_NOT_CONNECTED;
    }

    std::string bundleOptionStr;
    int32_t notificationId = -1;
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
            case 'i':
                notificationId = atoi(optarg);
                break;
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

    ret = NotificationHelper::CancelAsBundle(bundleOption, notificationId);
    if (ret == ERR_OK) {
        json data;
        OutputSuccess(data, resultReceiver_);
        return ERR_OK;
    }
    OutputApiError(ret, "取消通知",
        "示例: ohos-notificationManager cancelById "
        "--bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --notificationId 1",
        resultReceiver_);
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
        OutputError("ERR_INVALID_ARG", "hashcodes参数解析失败: JSON格式无效",
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
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "批量取消通知", "", resultReceiver_);
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
        resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::RunAsCancelByBundleCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "取消通知", "", resultReceiver_);
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
        resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::RunAsEnableNotificationCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "设置通知开关", "", resultReceiver_);
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
        resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::RunAsSetSlotFlagsCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "设置渠道标志", "", resultReceiver_);
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
            "--bundleOption \"{\\\"bundleName\\\":\\\"com.example\\\",\\\"uid\\\":10100}\" --flags 255",
            resultReceiver_);
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
        resultReceiver_);
    return ret;
}

ErrCode NotificationShellCommand::RunAsListAllNotificationCommand()
{
    if (ans_ == nullptr) {
        OutputApiError(ERR_ANS_SERVICE_NOT_CONNECTED, "查询通知", "", resultReceiver_);
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
            "示例: ohos-notificationManager listAllNotification", resultReceiver_);
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
    auto additionalParams = request->GetAdditionalData();
    if (additionalParams != nullptr) {
        AAFwk::WantParamWrapper wWrapper(*additionalParams);
        item["additionalParams"] = wWrapper.ToString();
    }
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
    auto extendInfo = request->GetExtendInfo();
    if (extendInfo != nullptr) {
        AAFwk::WantParamWrapper wWrapper(*extendInfo);
        item["extendInfo"] = wWrapper.ToString();
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
        auto extraInfo = liveContent->GetExtraInfo();
        if (extraInfo != nullptr) {
            AAFwk::WantParamWrapper wWrapper(*extraInfo);
            contentObj["extraInfo"] = wWrapper.ToString();
        }
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
