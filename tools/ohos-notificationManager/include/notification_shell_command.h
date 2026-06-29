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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_OHOS_NOTIFICATIONMANAGER_INCLUDE_NOTIFICATION_SHELL_COMMAND_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_OHOS_NOTIFICATIONMANAGER_INCLUDE_NOTIFICATION_SHELL_COMMAND_H

#include "shell_command.h"
#include "ans_notification.h"
#include "command_output.h"
#include "nlohmann/json.hpp"
#include "notification_request.h"
#include "notification_bundle_option.h"
#include "notification.h"
#include "notification_content.h"
#include "notification_basic_content.h"
#include <cstdint>
#include <memory>
#include <string>

namespace OHOS {
namespace Notification {

struct PublishOptions {
    int32_t notificationId = 0;
    int32_t slotType = 3;
    std::string contentJson;
    std::string label;
    std::string groupName;
    std::string sound;
    std::string appMessageId;
    std::string priorityNotificationType;
    std::string additionalParamsJson;
    std::string actionButtonsJson;
    std::string flagsStr;
    std::string templateJson;
    uint32_t badgeNumber = 0;
    int64_t autoDeletedTime = -1;
    bool isUpdateOnly = false;
    bool isAlertOneTime = false;
    bool isTapDismissed = false;
    bool isOngoing = false;
    bool isUnremovable = false;
    bool helpRequested = false;
};

class NotificationShellCommand : public OHOS::Notification::ShellCommand {
public:
    NotificationShellCommand(int argc, char *argv[]);

    ~NotificationShellCommand() override {};

private:
    ErrCode CreateCommandMap() override;
    ErrCode Init() override;
    ErrCode RunAsHelpCommand();
    ErrCode RunAsPublishCommand();
    ErrCode RunAsCancelByIdCommand();
    ErrCode RunAsBatchCancelCommand();
    ErrCode RunAsCancelByBundleCommand();
    ErrCode RunAsEnableNotificationCommand();
    ErrCode RunAsSetSlotFlagsCommand();
    ErrCode RunAsListAllNotificationCommand();

    ErrCode ParseBundleOption(const std::string &jsonStr,
        NotificationBundleOption &bundleOption);

    ErrCode ParsePublishOptions(PublishOptions &opts);
    ErrCode BuildNotificationContent(const std::string &contentJson,
        NotificationRequest &request);
    void BuildBasicContent(const std::string &cTitle, const std::string &cText,
        const std::string &cAdditionalText, NotificationRequest &request);
    ErrCode BuildLongTextContent(const nlohmann::json &contentObj,
        const std::string &cTitle, const std::string &cText,
        const std::string &cAdditionalText, NotificationRequest &request);
    ErrCode BuildMultilineContent(const nlohmann::json &contentObj,
        const std::string &cTitle, const std::string &cText,
        const std::string &cAdditionalText, NotificationRequest &request);
    ErrCode ValidatePublishRequiredOptions(const PublishOptions &opts);
    void ApplySimplePublishFields(const PublishOptions &opts, NotificationRequest &request);
    ErrCode ApplyPublishOptions(const PublishOptions &opts, NotificationRequest &request);
    ErrCode ParseAndApplyActionButtons(const std::string &jsonStr, NotificationRequest &request);
    ErrCode ParseAndApplyNotificationFlags(const std::string &jsonStr, NotificationRequest &request);
    ErrCode ParseAndApplyNotificationTemplate(const std::string &jsonStr, NotificationRequest &request);
    ErrCode ParseAndApplyAdditionalParams(const std::string &jsonStr, NotificationRequest &request);
    ErrCode ParseHashcodes(const std::string &jsonStr, std::vector<std::string> &hashcodes);

    void SerializeNotification(const sptr<Notification> &notif, nlohmann::json &item);
    void SerializeNotificationContent(
        const std::shared_ptr<NotificationContent> &content, nlohmann::json &contentObj);
    void SerializeBasicContent(
        const std::shared_ptr<NotificationBasicContent> &baseContent, nlohmann::json &contentObj);
    void SerializeLongTextContent(
        const std::shared_ptr<NotificationBasicContent> &baseContent, nlohmann::json &contentObj);
    void SerializeMultilineContent(
        const std::shared_ptr<NotificationBasicContent> &baseContent, nlohmann::json &contentObj);
    void SerializePictureContent(
        const std::shared_ptr<NotificationBasicContent> &baseContent, nlohmann::json &contentObj);
    void SerializeConversationContent(
        const std::shared_ptr<NotificationBasicContent> &baseContent, nlohmann::json &contentObj);
    void SerializeMediaContent(
        const std::shared_ptr<NotificationBasicContent> &baseContent, nlohmann::json &contentObj);
    void SerializeLiveViewContent(
        const std::shared_ptr<NotificationBasicContent> &baseContent, nlohmann::json &contentObj);
    void SerializeLocalLiveViewContent(
        const std::shared_ptr<NotificationBasicContent> &baseContent, nlohmann::json &contentObj);

    std::shared_ptr<AnsNotification> ans_;
};
}  // namespace Notification
}  // namespace OHOS
#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_TOOLS_OHOS_NOTIFICATIONMANAGER_INCLUDE_NOTIFICATION_SHELL_COMMAND_H
