/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_notification_manager_impl.h"
#include "inner_errors.h"
#include "cj_notification_enable.h"
#include "pixel_map_impl.h"

#include "notification_request.h"
#include "notification_constant.h"
#include "notification_content.h"
#include "notification_helper.h"
#include "notification_multiline_content.h"
#include "notification_normal_content.h"
#include "notification_picture_content.h"
#include "notification_long_text_content.h"
#include "notification_manager_log.h"

#include "ans_notification.h"
#include "singleton.h"
#include "securec.h"

namespace OHOS {
namespace CJSystemapi {
    using namespace OHOS::Notification;
    using namespace OHOS::CJSystemapi::Notification;

    static bool GetNotificationBasicContentDetailed(
        CNotificationBasicContent* contentResult,
        std::shared_ptr<NotificationBasicContent> basicContent)
    {
        char str[STR_MAX_SIZE] = {0};
        // title: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->title) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property title is empty");
            return false;
        }
        basicContent->SetTitle(std::string(str));
        LOGI("normal::title = %{public}s", str);

        // text: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->text) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property text is empty");
            return false;
        }
        basicContent->SetText(std::string(str));
        LOGI("normal::text = %{public}s", str);

        // additionalText: string
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->additionalText) != EOK) {
            return false;
        }
        basicContent->SetAdditionalText(std::string(str));
        LOGI("normal::additionalText = %{public}s", str);

        return true;
    }

    static bool GetNotificationLongTextContentDetailed(
        CNotificationLongTextContent* contentResult,
        std::shared_ptr<NotificationLongTextContent> &longContent)
    {
        char str[STR_MAX_SIZE] = {0};
        char longStr[LONG_STR_MAX_SIZE + 1] = {0};

        std::shared_ptr<CNotificationBasicContent> tempContent = std::make_shared<CNotificationBasicContent>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        if (!GetNotificationBasicContentDetailed(tempContent.get(), longContent)) {
            return false;
        }
        
        // longText: String
        if (strcpy_s(longStr, LONG_STR_MAX_SIZE + 1, contentResult->longText) != EOK) {
            return false;
        }
        if (strlen(longStr) == 0) {
            LOGE("Property longText is empty");
            return false;
        }
        longContent->SetLongText(std::string(longStr));
        LOGI("longText::longText = %{public}s", longStr);

        // briefText: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->briefText) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property briefText is empty");
            return false;
        }
        longContent->SetBriefText(std::string(str));
        LOGI("longText::briefText = %{public}s", str);

        // expandedTitle: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->expandedTitle) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property expandedTitle is empty");
            return false;
        }
        longContent->SetExpandedTitle(std::string(str));
        LOGI("longText::expandedTitle = %{public}s", str);

        return true;
    }

    static bool GetNotificationPictureContentDetailed(
        CNotificationPictureContent* contentResult,
        std::shared_ptr<OHOS::Notification::NotificationPictureContent> &pictureContent)
    {
        char str[STR_MAX_SIZE] = {0};

        std::shared_ptr<CNotificationBasicContent> tempContent = std::make_shared<CNotificationBasicContent>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        if (!GetNotificationBasicContentDetailed(tempContent.get(), pictureContent)) {
            return false;
        }

        // briefText: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->briefText) != EOK) {
            return false;
        }
        if (std::strlen(str) == 0) {
            LOGE("Property briefText is empty");
            return false;
        }
        pictureContent->SetBriefText(std::string(str));
        LOGI("longText::briefText = %{public}s", str);

        // expandedTitle: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->expandedTitle) != EOK) {
            return false;
        }
        if (std::strlen(str) == 0) {
            LOGE("Property expandedTitle is empty");
            return false;
        }
        pictureContent->SetExpandedTitle(std::string(str));
        LOGI("picture::expandedTitle = %{public}s", str);

        // picture: image.PixelMap
        auto pixelMap = FFI::FFIData::GetData<Media::PixelMapImpl>(contentResult->picture);
        if (pixelMap == nullptr) {
            LOGE("Invalid object pixelMap");
            return false;
        }
        pictureContent->SetBigPicture(pixelMap->GetRealPixelMap());

        return true;
    }

    static bool GetNotificationBasicContent(
        CNotificationBasicContent* contentResult,
        NotificationRequest &request)
    {
        std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
        if (normalContent == nullptr) {
            LOGE("normalContent is null");
            return false;
        }

        if (!GetNotificationBasicContentDetailed(contentResult, normalContent)) {
            return false;
        }
        request.SetContent(std::make_shared<NotificationContent>(normalContent));
        return true;
    }

    static bool GetNotificationLongTextContent(
        CNotificationLongTextContent* contentResult,
        NotificationRequest &request)
    {
        std::shared_ptr<OHOS::Notification::NotificationLongTextContent> longContent =
        std::make_shared<OHOS::Notification::NotificationLongTextContent>();
        if (longContent == nullptr) {
            LOGE("longContent is null");
            return false;
        }
        if (!GetNotificationLongTextContentDetailed(contentResult, longContent)) {
            return false;
        }
        
        request.SetContent(std::make_shared<NotificationContent>(longContent));
        return true;
    }

    static bool GetNotificationPictureContent(
        CNotificationPictureContent* contentResult,
        NotificationRequest &request)
    {
        std::shared_ptr<OHOS::Notification::NotificationPictureContent> pictureContent =
        std::make_shared<OHOS::Notification::NotificationPictureContent>();
        if (pictureContent == nullptr) {
            LOGE("pictureContent is null");
            return false;
        }

        if (!GetNotificationPictureContentDetailed(contentResult, pictureContent)) {
            return false;
        }

        request.SetContent(std::make_shared<NotificationContent>(pictureContent));
        return true;
    }

    static bool GetNotificationMultiLineContentLines(
        CNotificationMultiLineContent* result,
        std::shared_ptr<OHOS::Notification::NotificationMultiLineContent> &multiLineContent)
    {
        char str[STR_MAX_SIZE] = {0};
        int64_t length = result->lines.size;
        if (length == 0) {
            LOGE("The array is empty.");
            return false;
        }
        for (int64_t i = 0; i < length; i++) {
            if (strcpy_s(str, STR_MAX_SIZE, result->lines.head[i]) != EOK) {
                return false;
            }
            multiLineContent->AddSingleLine(std::string(str));
            LOGI("multiLine: lines : addSingleLine = %{public}s", str);
        }
        return true;
    }

    static bool GetNotificationMultiLineContent(
        CNotificationMultiLineContent* contentResult,
        NotificationRequest &request)
    {
        char str[STR_MAX_SIZE] = {0};

        std::shared_ptr<OHOS::Notification::NotificationMultiLineContent> multiLineContent =
        std::make_shared<OHOS::Notification::NotificationMultiLineContent>();
        if (multiLineContent == nullptr) {
            LOGE("multiLineContent is null");
            return false;
        }

        std::shared_ptr<CNotificationBasicContent> tempContent = std::make_shared<CNotificationBasicContent>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        if (!GetNotificationBasicContentDetailed(tempContent.get(), multiLineContent)) {
            return false;
        }

        // briefText: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->briefText) != EOK) {
            return false;
        }
        if (std::strlen(str) == 0) {
            LOGE("Property briefText is empty");
            return false;
        }
        multiLineContent->SetBriefText(std::string(str));
        LOGI("multiLine: briefText = %{public}s", str);

        // longTitle: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->longTitle)) {
            return false;
        }
        if (std::strlen(str) == 0) {
            LOGE("Property longTitle is empty");
            return false;
        }
        multiLineContent->SetExpandedTitle(std::string(str));
        LOGI("multiLine: longTitle = %{public}s", str);

        // lines: Array<String>
        if (!GetNotificationMultiLineContentLines(contentResult, multiLineContent)) {
            return false;
        }

        request.SetContent(std::make_shared<NotificationContent>(multiLineContent));
        return true;
    }

    static bool ContentTypeCJToC(const ContentType &inType, NotificationContent::Type &outType)
    {
        switch (inType) {
            case ContentType::NOTIFICATION_CONTENT_BASIC_TEXT:
                outType = NotificationContent::Type::BASIC_TEXT;
                break;
            case ContentType::NOTIFICATION_CONTENT_LONG_TEXT:
                outType = NotificationContent::Type::LONG_TEXT;
                break;
            case ContentType::NOTIFICATION_CONTENT_MULTILINE:
                outType = NotificationContent::Type::MULTILINE;
                break;
            case ContentType::NOTIFICATION_CONTENT_PICTURE:
                outType = NotificationContent::Type::PICTURE;
                break;
            case ContentType::NOTIFICATION_CONTENT_CONVERSATION:
                outType = NotificationContent::Type::CONVERSATION;
                break;
            case ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW:
                outType = NotificationContent::Type::LOCAL_LIVE_VIEW;
                break;
            case ContentType::NOTIFICATION_CONTENT_LIVE_VIEW:
                outType = NotificationContent::Type::LIVE_VIEW;
                break;
            default:
                LOGE("ContentType %{public}d is an invalid value", inType);
                return false;
        }
        return true;
    }

    static bool SlotTypeCJToC(const SlotType &inType, NotificationConstant::SlotType &outType)
    {
        switch (inType) {
            case SlotType::SOCIAL_COMMUNICATION:
                outType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
                break;
            case SlotType::SERVICE_INFORMATION:
                outType = NotificationConstant::SlotType::SERVICE_REMINDER;
                break;
            case SlotType::CONTENT_INFORMATION:
                outType = NotificationConstant::SlotType::CONTENT_INFORMATION;
                break;
            case SlotType::LIVE_VIEW:
                outType = NotificationConstant::SlotType::LIVE_VIEW;
                break;
            case SlotType::CUSTOMER_SERVICE:
                outType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
                break;
            case SlotType::UNKNOWN_TYPE:
            case SlotType::OTHER_TYPES:
                outType = NotificationConstant::SlotType::OTHER;
                break;
            default:
                LOGE("SlotType %{public}d is an invalid value", inType);
                return false;
        }
        return true;
    }

    static bool GetNotificationContent(CNotificationContent content, NotificationRequest &request)
    {
        NotificationContent::Type outType = NotificationContent::Type::NONE;
        if (!ContentTypeCJToC(ContentType(content.notificationContentType), outType)) {
            return false;
        }
        switch (outType) {
            case NotificationContent::Type::BASIC_TEXT:
                if (content.normal == nullptr || !GetNotificationBasicContent(content.normal, request)) {
                    return false;
                }
                break;
            case NotificationContent::Type::LONG_TEXT:
                if (content.longText == nullptr || !GetNotificationLongTextContent(content.longText, request)) {
                    return false;
                }
                break;
            case NotificationContent::Type::PICTURE:
                if (content.picture == nullptr || !GetNotificationPictureContent(content.picture, request)) {
                    return false;
                }
                break;
            case NotificationContent::Type::CONVERSATION:
                break;
            case NotificationContent::Type::MULTILINE:
                if (content.multiLine == nullptr || !GetNotificationMultiLineContent(content.multiLine, request)) {
                    return false;
                }
                break;
            case NotificationContent::Type::LOCAL_LIVE_VIEW:
                break;
            case NotificationContent::Type::LIVE_VIEW:
                break;
            default:
                return false;
        }
        return true;
    }

    static bool GetNotificationSlotType(int32_t slotType, NotificationRequest &request)
    {
        NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
        if (!SlotTypeCJToC(SlotType(slotType), outType)) {
            return false;
        }
        request.SetSlotType(outType);
        return true;
    }

    static bool GetNotificationSmallIcon(int64_t smallIcon, NotificationRequest request)
    {
        if (smallIcon != -1) {
            auto pixelMap = FFI::FFIData::GetData<Media::PixelMapImpl>(smallIcon);
            if (pixelMap == nullptr) {
                LOGE("Invalid object pixelMap");
                return false;
            }
            request.SetLittleIcon(pixelMap->GetRealPixelMap());
        }
        return true;
    }

    static bool GetNotificationLargeIcon(int64_t largeIcon, NotificationRequest request)
    {
        if (largeIcon != -1) {
            auto pixelMap = FFI::FFIData::GetData<Media::PixelMapImpl>(largeIcon);
            if (pixelMap == nullptr) {
                LOGE("Invalid object pixelMap");
                return false;
            }
            request.SetBigIcon(pixelMap->GetRealPixelMap());
        }
        return true;
    }

    static bool GetNotificationSupportDisplayDevices(
        CDistributedOptions* distributedOption,
        NotificationRequest request)
    {
        int64_t length = distributedOption->supportDisplayDevices.size;
        if (length == 0) {
            LOGE("The array is empty.");
            return false;
        }
        std::vector<std::string> devices;
        for (int64_t i = 0; i < length; i++) {
            char str[STR_MAX_SIZE] = {0};
            auto displayDevice = distributedOption->supportDisplayDevices.head[i];
            if (strcpy_s(str, STR_MAX_SIZE, displayDevice) != EOK) {
                return false;
            }
            devices.emplace_back(str);
            LOGI("supportDisplayDevices = %{public}s", str);
        }
        request.SetDevicesSupportDisplay(devices);
        return true;
    }

    static bool GetNotificationSupportOperateDevices(
        CDistributedOptions* distributedOption,
        NotificationRequest request)
    {
        int64_t length = distributedOption->supportOperateDevices.size;
        if (length == 0) {
            LOGE("The array is empty.");
            return false;
        }
        std::vector<std::string> devices;
        for (int64_t i = 0; i < length; i++) {
            char str[STR_MAX_SIZE] = {0};
            auto operateDevice = distributedOption->supportOperateDevices.head[i];
            if (strcpy_s(str, STR_MAX_SIZE, operateDevice) != EOK) {
                return false;
            }
            devices.emplace_back(str);
            LOGI("supportOperateDevices = %{public}s", str);
        }
        request.SetDevicesSupportOperate(devices);
        return true;
    }

    static bool GetNotificationRequestDistributedOptions(
        CDistributedOptions* distributedOption,
        NotificationRequest request)
    {
        if (distributedOption != nullptr) {
            // isDistributed?: boolean
            request.SetDistributed(distributedOption->isDistributed);

            // supportDisplayDevices?: Array<string>
            if (!GetNotificationSupportDisplayDevices(distributedOption, request)) {
                return false;
            }

            // supportOperateDevices?: Array<string>
            if (!GetNotificationSupportOperateDevices(distributedOption, request)) {
                return false;
            }
        }
        return true;
    }

    static bool GetNotificationRequestByNumber(CNotificationRequest cjRequest, NotificationRequest &request)
    {
        // id?: number
        int32_t id = cjRequest.id;
        request.SetNotificationId(id);

        // deliveryTime?: number
        int64_t deliveryTime = cjRequest.deliveryTime;
        request.SetDeliveryTime(deliveryTime);

        // autoDeletedTime?: number
        int64_t autoDeletedTime = cjRequest.autoDeletedTime;
        request.SetAutoDeletedTime(autoDeletedTime);

        // color?: number
        request.SetColor(cjRequest.color);

        // badgeIconStyle?: number
        int32_t badgeIconStyle = cjRequest.badgeIconStyle;
        request.SetBadgeIconStyle(static_cast<NotificationRequest::BadgeStyle>(badgeIconStyle));

        // badgeNumber?: number
        int32_t badgeNumber = cjRequest.badgeNumber;
        if (badgeNumber < 0) {
            LOGE("Wrong badge number.");
            return false;
        }
        request.SetBadgeNumber(badgeNumber);

        return true;
    }

    static bool GetNotificationRequestByString(CNotificationRequest cjRequest, NotificationRequest &request)
    {
        // label?: string
        char label[STR_MAX_SIZE] = {0};
        if (strcpy_s(label, STR_MAX_SIZE, cjRequest.label) != EOK) {
            return false;
        }
        request.SetLabel(std::string(label));

        // groupName?: string
        char groupName[STR_MAX_SIZE] = {0};
        if (strcpy_s(groupName, STR_MAX_SIZE, cjRequest.groupName) != EOK) {
            return false;
        }
        request.SetGroupName(std::string(groupName));

        return true;
    }

    static bool GetNotificationRequestByBool(CNotificationRequest cjRequest, NotificationRequest &request)
    {
        // isOngoing?: boolean
        bool isOngoing = cjRequest.isOngoing;
        request.SetInProgress(isOngoing);

        // isUnremovable?: boolean
        bool isUnremovable = cjRequest.isUnremovable;
        request.SetUnremovable(isUnremovable);

        // tapDismissed?: boolean
        bool tapDismissed = cjRequest.tapDismissed;
        request.SetTapDismissed(tapDismissed);
        
        // colorEnabled?: boolean
        bool colorEnabled = cjRequest.colorEnabled;
        request.SetColorEnabled(colorEnabled);

        // isAlertOnce?: boolean
        bool isAlertOnce = cjRequest.isAlertOnce;
        request.SetAlertOneTime(isAlertOnce);

        // isStopwatch?: boole
        bool isStopwatch = cjRequest.isStopwatch;
        request.SetShowStopwatch(isStopwatch);

        // isCountDown?: boolean
        bool isCountDown = cjRequest.isCountDown;
        request.SetCountdownTimer(isCountDown);

        // showDeliveryTime?: boolean
        bool showDeliveryTime = cjRequest.showDeliveryTime;
        request.SetShowDeliveryTime(showDeliveryTime);

        return true;
    }

    static bool GetNotificationRequestByCustom(CNotificationRequest cjRequest, NotificationRequest &request)
    {
        // content: NotificationContent
        if (!GetNotificationContent(cjRequest.notificationContent, request)) {
            return false;
        }
        // slotType?: notification.SlotType
        if (!GetNotificationSlotType(cjRequest.notificationSlotType, request)) {
            return false;
        }
        // smallIcon?: image.PixelMap
        if (!GetNotificationSmallIcon(cjRequest.smallIcon, request)) {
            return false;
        }
        // largeIcon?: image.PixelMap
        if (!GetNotificationLargeIcon(cjRequest.largeIcon, request)) {
            return false;
        }
        // distributedOption?:DistributedOptions
        if (!GetNotificationRequestDistributedOptions(cjRequest.distributedOption, request)) {
            return false;
        }

        return true;
    }

    static bool ParseParameters(CNotificationRequest params, NotificationRequest &request)
    {
        if (!GetNotificationRequestByNumber(params, request)) {
            return false;
        }

        if (!GetNotificationRequestByString(params, request)) {
            return false;
        }

        if (!GetNotificationRequestByBool(params, request)) {
            return false;
        }

        if (!GetNotificationRequestByCustom(params, request)) {
            return false;
        }
        return true;
    }

    int NotificationManagerImpl::Publish(CNotificationRequest cjRequest)
    {
        LOGI("start make a NotificationRequest");
        NotificationRequest request;
        LOGI("start parse the parameters of NotificationRequest");
        if (!ParseParameters(cjRequest, request)) {
            return ERROR_PARAM_INVALID;
        }
        int code = NotificationHelper::PublishNotification(request);
        return ErrorToExternal(code);
    }

    int NotificationManagerImpl::Cancel(int32_t id, const char* label)
    {
        int code = NotificationHelper::CancelNotification(label, id);
        return ErrorToExternal(code);
    }

    int NotificationManagerImpl::CancelAll()
    {
        int code = NotificationHelper::CancelAllNotifications();
        return ErrorToExternal(code);
    }

    int NotificationManagerImpl::AddSlot(int32_t type)
    {
        NotificationConstant::SlotType slot = NotificationConstant::SlotType::OTHER;
        if (!SlotTypeCJToC(SlotType(type), slot)) {
            return false;
        }
        int code = NotificationHelper::AddNotificationSlot(slot);
        return ErrorToExternal(code);
    }

    RetDataBool NotificationManagerImpl::IsNotificationEnabled()
    {
        RetDataBool ret = { .code = EINVAL, .data = false };
        IsEnableParams params {};
        bool allowed = false;
        int errorCode;
        if (params.hasBundleOption) {
            LOGI("option.bundle : %{public}s option.uid : %{public}d",
                params.option.GetBundleName().c_str(),
                params.option.GetUid());
            errorCode = NotificationHelper::IsAllowedNotify(params.option, allowed);
        } else if (params.hasUserId) {
            LOGI("userId : %{public}d", params.userId);
            errorCode = NotificationHelper::IsAllowedNotify(params.userId, allowed);
        } else {
            errorCode = NotificationHelper::IsAllowedNotifySelf(allowed);
        }
        ret.code = ErrorToExternal(errorCode);
        ret.data = allowed;
        LOGI("errorCode : %{public}d, allowed : %{public}d",
            errorCode, allowed);
        return ret;
    }

    int NotificationManagerImpl::SetBadgeNumber(int32_t badgeNumber)
    {
        int code = NotificationHelper::SetBadgeNumber(badgeNumber);
        return ErrorToExternal(code);
    }

    int NotificationManagerImpl::RequestEnableNotification()
    {
        IsEnableParams params {};
        std::string deviceId {""};
        sptr<AnsDialogHostClient> client = nullptr;
        if (!AnsDialogHostClient::CreateIfNullptr(client)) {
            LOGI("dialog is popping %{public}d.", ERR_ANS_DIALOG_IS_POPPING)
            return ErrorToExternal(ERR_ANS_DIALOG_IS_POPPING);
        }
        int code = NotificationHelper::RequestEnableNotification(deviceId, client, params.callerToken);
        LOGI("done, code is %{public}d.", code)
        return ErrorToExternal(code);
    }

    int NotificationManagerImpl::RequestEnableNotificationWithContext(sptr<AbilityRuntime::CJAbilityContext> context)
    {
        IsEnableParams params {};
        sptr<IRemoteObject> callerToken = context->GetToken();
        params.callerToken = callerToken;
        sptr<AnsDialogHostClient> client = nullptr;
        params.hasCallerToken = true;
        std::string deviceId {""};
        if (!AnsDialogHostClient::CreateIfNullptr(client)) {
            LOGI("dialog is popping %{public}d.", ERR_ANS_DIALOG_IS_POPPING)
            return ErrorToExternal(ERR_ANS_DIALOG_IS_POPPING);
        }
        int code = NotificationHelper::RequestEnableNotification(deviceId, client, params.callerToken);
        LOGI("done, code is %{public}d.", code)
        return ErrorToExternal(code);
    }

    RetDataBool NotificationManagerImpl::IsDistributedEnabled()
    {
        RetDataBool ret = { .code = EINVAL, .data = false };
        bool enable = false;
        int code = NotificationHelper::IsDistributedEnabled(enable);
        LOGI("IsDistributedEnabled enable = %{public}d", enable);
        ret.code = code;
        ret.data = enable;
        return ret;
    }
} // CJSystemapi
} // namespace OHOS