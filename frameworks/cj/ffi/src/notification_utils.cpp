/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "notification_utils.h"
#include "notification_manager_log.h"

namespace OHOS {
namespace CJSystemapi {
namespace Notification {
    using namespace OHOS::FFI;
    using namespace OHOS::Notification;

    char *MallocCString(const std::string &origin)
    {
        if (origin.empty()) {
            return nullptr;
        }
        auto len = origin.length() + 1;
        char *res = static_cast<char *>(malloc(sizeof(char) * len));
        if (res == nullptr) {
            return nullptr;
        }
        return std::char_traits<char>::copy(res, origin.c_str(), len);
    }

    bool GetNotificationSupportDisplayDevices(
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

    bool GetNotificationSupportOperateDevices(
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

    bool GetNotificationRequestDistributedOptions(
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

    bool GetNotificationRequestByNumber(CNotificationRequest cjRequest, NotificationRequest &request)
    {
        // id?: int32_t
        int32_t id = cjRequest.id;
        request.SetNotificationId(id);

        // deliveryTime?: int64_t
        int64_t deliveryTime = cjRequest.deliveryTime;
        request.SetDeliveryTime(deliveryTime);

        // autoDeletedTime?: int64_t
        int64_t autoDeletedTime = cjRequest.autoDeletedTime;
        request.SetAutoDeletedTime(autoDeletedTime);

        // color?: uint32_t
        request.SetColor(cjRequest.color);

        // badgeIconStyle?: int32_t
        int32_t badgeIconStyle = cjRequest.badgeIconStyle;
        request.SetBadgeIconStyle(static_cast<NotificationRequest::BadgeStyle>(badgeIconStyle));

        // badgeNumber?: uint32_t
        uint32_t badgeNumber = cjRequest.badgeNumber;
        if (badgeNumber < 0) {
            LOGE("Wrong badge number.");
            return false;
        }
        request.SetBadgeNumber(badgeNumber);

        return true;
    }

    bool GetNotificationRequestByString(CNotificationRequest cjRequest, NotificationRequest &request)
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

        // groupName?: string
        char appMessageId[STR_MAX_SIZE] = {0};
        if (strcpy_s(appMessageId, STR_MAX_SIZE, cjRequest.appMessageId) != EOK) {
            return false;
        }
        request.SetAppMessageId(std::string(appMessageId));

        return true;
    }

    bool GetNotificationRequestByBool(CNotificationRequest cjRequest, NotificationRequest &request)
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

    bool GetNotificationRequestByCustom(CNotificationRequest cjRequest, NotificationRequest &request)
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

    bool GetNotificationBasicContentDetailed(CNotificationBasicContent* contentResult,
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
        // text: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->text) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property text is empty");
            return false;
        }
        basicContent->SetText(std::string(str));
        // additionalText: string
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->additionalText) != EOK) {
            return false;
        }
        basicContent->SetAdditionalText(std::string(str));
        
        // lockScreenPicture?: pixelMap
        if (contentResult->lockscreenPicture != -1) {
            auto pixelMap = FFIData::GetData<Media::PixelMapImpl>(contentResult->lockscreenPicture);
            if (pixelMap == nullptr) {
                LOGE("Invalid object pixelMap");
                return false;
            }
            basicContent->SetLockScreenPicture(pixelMap->GetRealPixelMap());
        }
        return true;
    }

    bool GetNotificationBasicContent(CNotificationBasicContent* contentResult, NotificationRequest &request)
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

    bool GetNotificationLongTextContentDetailed(
        CNotificationLongTextContent* contentResult,
        std::shared_ptr<NotificationLongTextContent> &longContent)
    {
        char str[STR_MAX_SIZE] = {0};
        char long_str[LONG_STR_MAX_SIZE + 1] = {0};

        std::shared_ptr<CNotificationBasicContent> tempContent = std::make_shared<CNotificationBasicContent>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        tempContent->lockscreenPicture = contentResult->lockscreenPicture;
        if (!GetNotificationBasicContentDetailed(tempContent.get(), longContent)) {
            return false;
        }
        
        // longText: String
        if (strcpy_s(long_str, LONG_STR_MAX_SIZE + 1, contentResult->longText) != EOK) {
            return false;
        }
        if (strlen(long_str) == 0) {
            LOGE("Property longText is empty");
            return false;
        }
        longContent->SetLongText(std::string(long_str));

        // briefText: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->briefText) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property briefText is empty");
            return false;
        }
        longContent->SetBriefText(std::string(str));

        // expandedTitle: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->expandedTitle) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property expandedTitle is empty");
            return false;
        }
        longContent->SetExpandedTitle(std::string(str));

        return true;
    }

    bool GetNotificationLongTextContent(
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

    bool GetNotificationPictureContentDetailed(
        CNotificationPictureContent* contentResult,
        std::shared_ptr<NotificationPictureContent> &pictureContent)
    {
        char str[STR_MAX_SIZE] = {0};

        std::shared_ptr<CNotificationBasicContent> tempContent = std::make_shared<CNotificationBasicContent>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        tempContent->lockscreenPicture = contentResult->lockscreenPicture;
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

        // expandedTitle: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->expandedTitle) != EOK) {
            return false;
        }
        if (std::strlen(str) == 0) {
            LOGE("Property expandedTitle is empty");
            return false;
        }
        pictureContent->SetExpandedTitle(std::string(str));

        // picture: image.PixelMap
        auto pixelMap = FFIData::GetData<Media::PixelMapImpl>(contentResult->picture);
        if (pixelMap == nullptr) {
            LOGE("Invalid object pixelMap");
            return false;
        }
        pictureContent->SetBigPicture(pixelMap->GetRealPixelMap());

        return true;
    }

    bool GetNotificationPictureContent(
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

    bool GetNotificationMultiLineContentLines(
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
        }
        return true;
    }

    bool GetNotificationMultiLineContent(
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
        tempContent->lockscreenPicture = contentResult->lockscreenPicture;
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

        // longTitle: String
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->longTitle) != EOK) {
            return false;
        }
        if (std::strlen(str) == 0) {
            LOGE("Property longTitle is empty");
            return false;
        }
        multiLineContent->SetExpandedTitle(std::string(str));

        // lines: Array<String>
        if (!GetNotificationMultiLineContentLines(contentResult, multiLineContent)) {
            return false;
        }

        request.SetContent(std::make_shared<NotificationContent>(multiLineContent));
        return true;
    }

    bool GetNotificationLocalLiveViewCapsule(CNotificationSystemLiveViewContent* contentResult,
        std::shared_ptr<NotificationLocalLiveViewContent> &content)
    {
        char str[STR_MAX_SIZE] = {0};
        NotificationCapsule capsule;
        if (strcpy_s(str, STR_MAX_SIZE, contentResult->capsule.title) != EOK) {
            LOGE("copy capsule.title failed");
            return false;
        }
        capsule.SetTitle(std::string(str));

        if (strcpy_s(str, STR_MAX_SIZE, contentResult->capsule.backgroundColor) != EOK) {
            LOGE("copy capsule.backgroundColor failed");
            return false;
        }
        capsule.SetBackgroundColor(std::string(str));

        if (contentResult->capsule.icon != -1) {
            auto pixelMap = FFIData::GetData<Media::PixelMapImpl>(contentResult->capsule.icon);
            if (pixelMap == nullptr) {
                LOGE("Invalid object pixelMap");
                return false;
            }
            capsule.SetIcon(pixelMap->GetRealPixelMap());
        }

        content->SetCapsule(capsule);
        content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE);
        return true;
    }

    bool GetNotificationLocalLiveViewButton(CNotificationSystemLiveViewContent* contentResult,
        std::shared_ptr<NotificationLocalLiveViewContent> &content)
    {
        char str[STR_MAX_SIZE] = {0};
        NotificationLocalLiveViewButton button;
        int64_t length = contentResult->button.names.size;
        for (int64_t i = 0; i < length; i++) {
            if (strcpy_s(str, STR_MAX_SIZE, contentResult->button.names.head[i]) != EOK) {
                LOGE("copy button.names failed");
                return false;
            }
            button.addSingleButtonName(std::string(str));
        }

        length = contentResult->button.icons.size;
        for (int64_t i = 0; i < length; i++) {
            int64_t id = contentResult->button.icons.head[i];
            auto pixelMap = FFIData::GetData<Media::PixelMapImpl>(id);
            if (pixelMap == nullptr) {
                LOGE("Invalid object pixelMap");
                return false;
            }
            auto pix = pixelMap->GetRealPixelMap();
            if (pix != nullptr && static_cast<uint32_t>(pix->GetByteCount()) <= MAX_ICON_SIZE) {
                button.addSingleButtonIcon(pix);
            } else {
                LOGE("Invalid pixelMap object or pixelMap is over size.");
                return false;
            }
        }
        content->SetButton(button);
        content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON);
        return true;
    }

    bool GetNotificationLocalLiveViewProgress(CNotificationSystemLiveViewContent* contentResult,
        std::shared_ptr<NotificationLocalLiveViewContent> &content)
    {
        NotificationProgress progress;
        if (contentResult->progress.maxValue < 0 || contentResult->progress.currentValue < 0) {
            LOGE("Wrong argument value. Number expected.");
            return false;
        }
        progress.SetMaxValue(contentResult->progress.maxValue);
        progress.SetCurrentValue(contentResult->progress.currentValue);
        progress.SetIsPercentage(contentResult->progress.isPercentage);

        content->SetProgress(progress);
        content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::PROGRESS);
        return true;
    }

    bool GetNotificationLocalLiveViewTime(CNotificationSystemLiveViewContent* contentResult,
        std::shared_ptr<NotificationLocalLiveViewContent> &content)
    {
        NotificationTime time;
        if (contentResult->time.initialTime < 0) {
            return false;
        }
        time.SetInitialTime(contentResult->time.initialTime);
        content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::INITIAL_TIME);
        time.SetIsCountDown(contentResult->time.isCountDown);
        time.SetIsPaused(contentResult->time.isPaused);
        time.SetIsInTitle(contentResult->time.isInTitle);
        
        content->SetTime(time);
        content->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::TIME);

        return true;
    }
    
    bool GetNotificationLocalLiveViewContentDetailed(CNotificationSystemLiveViewContent* contentResult,
        std::shared_ptr<NotificationLocalLiveViewContent> &content)
    {
        // title, text
        std::shared_ptr<CNotificationBasicContent> tempContent = std::make_shared<CNotificationBasicContent>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        tempContent->lockscreenPicture = contentResult->lockscreenPicture;
        if (!GetNotificationBasicContentDetailed(tempContent.get(), content)) {
            LOGE("Basic content get fail.");
            return false;
        }

        // typeCode
        content->SetType(contentResult->typeCode);

        // capsule?
        if (!GetNotificationLocalLiveViewCapsule(contentResult, content)) {
            LOGE("GetNotificationLocalLiveViewCapsule fail.");
            return false;
        }

        // button?
        if (!GetNotificationLocalLiveViewButton(contentResult, content)) {
            LOGE("GetNotificationLocalLiveViewButton fail.");
            return false;
        }

        // progress?
        if (!GetNotificationLocalLiveViewProgress(contentResult, content)) {
            LOGE("GetNotificationLocalLiveViewProgress fail.");
            return false;
        }

        // time?
        if (!GetNotificationLocalLiveViewTime(contentResult, content)) {
            LOGE("GetNotificationLocalLiveViewTime fail.");
            return false;
        }

        return true;
    }

    bool GetNotificationLocalLiveViewContent(CNotificationSystemLiveViewContent* contentResult,
        NotificationRequest &request)
    {
        std::shared_ptr<NotificationLocalLiveViewContent> localLiveViewContent =
            std::make_shared<NotificationLocalLiveViewContent>();
        if (localLiveViewContent == nullptr) {
            LOGE("localLiveViewContent is null");
            return false;
        }

        if (!GetNotificationLocalLiveViewContentDetailed(contentResult, localLiveViewContent)) {
            return false;
        }

        request.SetContent(std::make_shared<NotificationContent>(localLiveViewContent));

        // set isOnGoing of live view true
        request.SetInProgress(true);
        return true;
    }

    bool SlotTypeCJToC(const SlotType &inType, NotificationConstant::SlotType &outType)
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

    bool SlotTypeCToCJ(const NotificationConstant::SlotType &inType, SlotType &outType)
    {
        switch (inType) {
            case NotificationConstant::SlotType::CUSTOM:
                outType = SlotType::UNKNOWN_TYPE;
                break;
            case NotificationConstant::SlotType::SOCIAL_COMMUNICATION:
                outType = SlotType::SOCIAL_COMMUNICATION;
                break;
            case NotificationConstant::SlotType::SERVICE_REMINDER:
                outType = SlotType::SERVICE_INFORMATION;
                break;
            case NotificationConstant::SlotType::CONTENT_INFORMATION:
                outType = SlotType::CONTENT_INFORMATION;
                break;
            case NotificationConstant::SlotType::LIVE_VIEW:
                outType = SlotType::LIVE_VIEW;
                break;
            case NotificationConstant::SlotType::CUSTOMER_SERVICE:
                outType = SlotType::CUSTOMER_SERVICE;
                break;
            case NotificationConstant::SlotType::OTHER:
                outType = SlotType::OTHER_TYPES;
                break;
            default:
                LOGE("SlotType %{public}d is an invalid value", inType);
                return false;
        }
        return true;
    }

    bool SlotLevelCToCJ(const NotificationSlot::NotificationLevel &inLevel, SlotLevel &outLevel)
    {
        switch (inLevel) {
            case NotificationSlot::NotificationLevel::LEVEL_NONE:
            case NotificationSlot::NotificationLevel::LEVEL_UNDEFINED:
                outLevel = SlotLevel::LEVEL_NONE;
                break;
            case NotificationSlot::NotificationLevel::LEVEL_MIN:
                outLevel = SlotLevel::LEVEL_MIN;
                break;
            case NotificationSlot::NotificationLevel::LEVEL_LOW:
                outLevel = SlotLevel::LEVEL_LOW;
                break;
            case NotificationSlot::NotificationLevel::LEVEL_DEFAULT:
                outLevel = SlotLevel::LEVEL_DEFAULT;
                break;
            case NotificationSlot::NotificationLevel::LEVEL_HIGH:
                outLevel = SlotLevel::LEVEL_HIGH;
                break;
            default:
                LOGE("SlotLevel %{public}d is an invalid value", inLevel);
                return false;
        }
        return true;
    }

    bool ContentTypeCJToC(const ContentType &inType, NotificationContent::Type &outType)
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

    bool ContentTypeCToCJ(const NotificationContent::Type &inType, ContentType &outType)
    {
        switch (inType) {
            case NotificationContent::Type::BASIC_TEXT:
                outType = ContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
                break;
            case NotificationContent::Type::LONG_TEXT:
                outType = ContentType::NOTIFICATION_CONTENT_LONG_TEXT;
                break;
            case NotificationContent::Type::MULTILINE:
                outType = ContentType::NOTIFICATION_CONTENT_MULTILINE;
                break;
            case NotificationContent::Type::PICTURE:
                outType = ContentType::NOTIFICATION_CONTENT_PICTURE;
                break;
            case NotificationContent::Type::CONVERSATION:
                outType = ContentType::NOTIFICATION_CONTENT_CONVERSATION;
                break;
            case NotificationContent::Type::LOCAL_LIVE_VIEW:
                outType = ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW;
                break;
            case NotificationContent::Type::LIVE_VIEW:
                outType = ContentType::NOTIFICATION_CONTENT_LIVE_VIEW;
                break;
            default:
                LOGE("ContentType %{public}d is an invalid value", inType);
                return false;
        }
        return true;
    }

    bool GetNotificationSlotType(int32_t slotType, NotificationRequest &request)
    {
        NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
        if (!SlotTypeCJToC(SlotType(slotType), outType)) {
            return false;
        }
        request.SetSlotType(outType);
        return true;
    }

    bool GetNotificationSmallIcon(int64_t smallIcon, NotificationRequest &request)
    {
        if (smallIcon != -1) {
            auto pixelMap = FFIData::GetData<Media::PixelMapImpl>(smallIcon);
            if (pixelMap == nullptr) {
                LOGE("Invalid object pixelMap");
                return false;
            }
            request.SetLittleIcon(pixelMap->GetRealPixelMap());
        }
        return true;
    }

    bool GetNotificationLargeIcon(int64_t largeIcon, NotificationRequest &request)
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

    bool GetNotificationContent(CNotificationContent &content, NotificationRequest &request)
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
                if (content.systemLiveView == nullptr ||
                    !GetNotificationLocalLiveViewContent(content.systemLiveView, request)) {
                    return false;
                }
                break;
            case NotificationContent::Type::LIVE_VIEW:
                break;
            default:
                return false;
        }
        return true;
    }

    bool SetNotificationSlot(const NotificationSlot &slot, CNotificationSlot &notificationSlot)
    {
        // type: SlotType
        SlotType outType = SlotType::UNKNOWN_TYPE;
        if (!SlotTypeCToCJ(slot.GetType(), outType)) {
            LOGE("SetNotificationSlot SlotTypeCToCJ failed.");
            return false;
        }
        // level?: int32_t
        SlotLevel outLevel = SlotLevel::LEVEL_NONE;
        if (!SlotLevelCToCJ(slot.GetLevel(), outLevel)) {
            LOGE("SetNotificationSlot SlotLevelCToCJ failed.");
            return false;
        }
        notificationSlot.notificationType = static_cast<int32_t>(outType);
        notificationSlot.level = static_cast<int32_t>(outLevel);

        notificationSlot.desc = MallocCString(slot.GetDescription()); // desc?: string
        notificationSlot.badgeFlag = slot.IsShowBadge(); // badgeFlag?: bool
        notificationSlot.bypassDnd = slot.IsEnableBypassDnd(); // bypassDnd?: bool
        // lockscreenVisibility?: int32_t
        notificationSlot.lockscreenVisibility = static_cast<int32_t>(slot.GetLockScreenVisibleness());
        notificationSlot.vibrationEnabled = slot.CanVibrate(); // vibrationEnabled?: bool
        notificationSlot.sound = MallocCString(slot.GetSound().ToString()); // sound?: string
        notificationSlot.lightEnabled = slot.CanEnableLight(); // lightEnabled?: bool
        notificationSlot.lightColor = slot.GetLedLightColor(); // lightColor?: int32_t

        // vibrationValues?: Array<int64_t>
        auto vec = slot.GetVibrationStyle();
        CArrI64 vibrationValues = { .head = NULL, .size = 0 };
        vibrationValues.size = static_cast<int64_t>(vec.size());
        if (vibrationValues.size > 0) {
            int64_t* head = static_cast<int64_t *>(malloc(sizeof(int64_t) * vec.size()));
            if (head == nullptr) {
                free(notificationSlot.desc);
                free(notificationSlot.sound);
                notificationSlot.desc = nullptr;
                notificationSlot.sound = nullptr;
                LOGE("SetNotificationSlot malloc vibrationValues.head failed.");
                return false;
            }
            int i = 0;
            for (auto value : vec) {
                head[i++] = static_cast<int64_t>(value);
            }
            vibrationValues.head = head;
        }
        notificationSlot.vibrationValues = vibrationValues;
        notificationSlot.enabled = slot.GetEnable(); // enabled?: boolean
        return true;
    }

    void SetNotificationRequestByString(
        const NotificationRequest *request,
        CNotificationRequest &notificationRequest)
    {
        // label?: string
        notificationRequest.label = MallocCString(request->GetLabel());

        // groupName?: string
        notificationRequest.groupName = MallocCString(request->GetGroupName());

        // readonly creatorBundleName?: string
        notificationRequest.creatorBundleName = MallocCString(request->GetCreatorBundleName());
    }

    bool SetNotificationRequestByNumber(
        const NotificationRequest *request,
        CNotificationRequest &notificationRequest)
    {
        // id?: int32_t
        notificationRequest.id = request->GetNotificationId();

        // slotType?: SlotType
        SlotType outType = SlotType::UNKNOWN_TYPE;
        if (!SlotTypeCToCJ(request->GetSlotType(), outType)) {
            return false;
        }
        notificationRequest.notificationSlotType = static_cast<int32_t>(outType);

        // deliveryTime?: int32_t
        notificationRequest.deliveryTime = request->GetDeliveryTime();

        // autoDeletedTime?: int32_t
        notificationRequest.autoDeletedTime = request->GetAutoDeletedTime();

        // color ?: int32_t
        notificationRequest.color = request->GetColor();

        // badgeIconStyle ?: int32_t
        notificationRequest.badgeIconStyle = static_cast<int32_t>(request->GetBadgeIconStyle());

        // readonly creatorUid?: int32_t
        notificationRequest.creatorUid = request->GetCreatorUid();

        // readonly creatorPid?: int32_t
        notificationRequest.creatorPid = request->GetCreatorPid();

        // badgeNumber?: uint32_t
        notificationRequest.badgeNumber = request->GetBadgeNumber();

        return true;
    }

    void SetNotificationRequestByBool(
        const NotificationRequest *request,
        CNotificationRequest &notificationRequest)
    {
        // isOngoing?: boolean
        notificationRequest.isOngoing = request->IsInProgress();

        // isUnremovable?: boolean
        notificationRequest.isUnremovable = request->IsUnremovable();

        // tapDismissed?: boolean
        notificationRequest.tapDismissed = request->IsTapDismissed();

        // colorEnabled?: boolean
        notificationRequest.colorEnabled = request->IsColorEnabled();

        // isAlertOnce?: boolean
        notificationRequest.isAlertOnce = request->IsAlertOneTime();

        // isStopwatch?: boolean
        notificationRequest.isStopwatch = request->IsShowStopwatch();

        // isCountDown?: boolean
        notificationRequest.isCountDown = request->IsCountdownTimer();

        // isFloatingIcon?: boolean
        notificationRequest.isFloatingIcon = request->IsFloatingIcon();

        // showDeliveryTime?: boolean
        notificationRequest.showDeliveryTime = request->IsShowDeliveryTime();
    }

    void SetNotificationRequestByPixelMap(
        const NotificationRequest *request,
        CNotificationRequest &notificationRequest)
    {
        // smallIcon?: image.PixelMap
        std::shared_ptr<Media::PixelMap> littleIcon = request->GetLittleIcon();
        notificationRequest.smallIcon = -1;
        if (littleIcon) {
            auto native = FFIData::Create<Media::PixelMapImpl>(littleIcon);
            if (native != nullptr) {
                notificationRequest.smallIcon = native->GetID();
            }
        }

        // largeIcon?: image.PixelMap
        notificationRequest.largeIcon = -1;
        std::shared_ptr<Media::PixelMap> largeIcon = request->GetBigIcon();
        if (largeIcon) {
            auto native = FFIData::Create<Media::PixelMapImpl>(largeIcon);
            if (native != nullptr) {
                notificationRequest.largeIcon = native->GetID();
            }
        }
    }

    static void freeNotificationBasicContent(CNotificationBasicContent* normal)
    {
        free(normal->title);
        free(normal->text);
        free(normal->additionalText);
        normal->title = nullptr;
        normal->text = nullptr;
        normal->additionalText = nullptr;
    }

    bool SetNotificationBasicContent(
        const NotificationBasicContent *basicContent,
        CNotificationBasicContent* normal)
    {
        if (basicContent == nullptr || normal == nullptr) {
            return false;
        }

        // title: string
        normal->title = MallocCString(basicContent->GetTitle());

        // text: string
        normal->text = MallocCString(basicContent->GetText());

        // additionalText?: string
        normal->additionalText = MallocCString(basicContent->GetAdditionalText());
        
        // lockScreenPicture?: pixelMap
        normal->lockscreenPicture = -1;
        if (basicContent->GetLockScreenPicture()) {
            std::shared_ptr<Media::PixelMap> pix = basicContent->GetLockScreenPicture();
            if (pix == nullptr) {
                LOGE("Invalid object pixelMap");
                freeNotificationBasicContent(normal);
                return false;
            }
            auto native = FFIData::Create<Media::PixelMapImpl>(pix);
            if (native == nullptr) {
                LOGE("Invalid object pixelMap");
                freeNotificationBasicContent(normal);
                return false;
            }
            normal->lockscreenPicture = native->GetID();
        }
        return true;
    }

    static void freeNotificationLongTextContent(CNotificationLongTextContent* longText)
    {
        free(longText->title);
        free(longText->text);
        free(longText->additionalText);
        free(longText->longText);
        free(longText->briefText);
        free(longText->expandedTitle);
        longText->title = nullptr;
        longText->text = nullptr;
        longText->additionalText = nullptr;
        longText->longText = nullptr;
        longText->briefText = nullptr;
        longText->expandedTitle = nullptr;
    }

    bool SetNotificationLongTextContent(
        NotificationBasicContent *basicContent,
        CNotificationLongTextContent* longText)
    {
        if (basicContent == nullptr) {
            LOGE("basicContent is null.");
            return false;
        }
        if (longText == nullptr) {
            LOGE("malloc CNotificationLongTextContent failed, longText is null.");
            return false;
        }

        OHOS::Notification::NotificationLongTextContent *longTextContent =
            static_cast<OHOS::Notification::NotificationLongTextContent *>(basicContent);
        if (longTextContent == nullptr) {
            LOGE("longTextContent is null");
            return false;
        }
        // title: string
        longText->title = MallocCString(longTextContent->GetTitle());
        // text: string
        longText->text = MallocCString(longTextContent->GetText());
        // additionalText?: string
        longText->additionalText = MallocCString(longTextContent->GetAdditionalText());
        // longText: string
        longText->longText = MallocCString(longTextContent->GetLongText());
        // briefText: string
        longText->briefText = MallocCString(longTextContent->GetBriefText());
        // expandedTitle: string
        longText->expandedTitle = MallocCString(longTextContent->GetExpandedTitle());
        // lockScreenPicture?: pixelMap
        longText->lockscreenPicture = -1;
        if (longTextContent->GetLockScreenPicture()) {
            std::shared_ptr<Media::PixelMap> pix = longTextContent->GetLockScreenPicture();
            if (pix == nullptr) {
                LOGE("Invalid object pixelMap");
                freeNotificationLongTextContent(longText);
                return false;
            }
            auto native = FFIData::Create<Media::PixelMapImpl>(pix);
            if (native == nullptr) {
                LOGE("Invalid object pixelMap");
                freeNotificationLongTextContent(longText);
                return false;
            }
            longText->lockscreenPicture = native->GetID();
        }
        return true;
    }

    static void freeNotificationPictureContent(CNotificationPictureContent* picture)
    {
        free(picture->title);
        free(picture->text);
        free(picture->additionalText);
        free(picture->briefText);
        free(picture->expandedTitle);
        picture->title = nullptr;
        picture->text = nullptr;
        picture->additionalText = nullptr;
        picture->briefText = nullptr;
        picture->expandedTitle = nullptr;
    }

    bool SetNotificationPictureContent(NotificationBasicContent *basicContent,
        CNotificationPictureContent* picture)
    {
        if (basicContent == nullptr) {
            LOGE("basicContent is null");
            return false;
        }
        OHOS::Notification::NotificationPictureContent *pictureContent =
            static_cast<OHOS::Notification::NotificationPictureContent *>(basicContent);
        if (pictureContent == nullptr) {
            LOGE("pictureContent is null");
            return false;
        }
        // title、text: string
        picture->title = MallocCString(pictureContent->GetTitle());
        picture->text = MallocCString(pictureContent->GetText());
        // additionalText?: string
        picture->additionalText = MallocCString(pictureContent->GetAdditionalText());
        // briefText、expandedTitle: string
        picture->briefText = MallocCString(pictureContent->GetBriefText());
        picture->expandedTitle = MallocCString(pictureContent->GetExpandedTitle());
        // picture: image.PixelMap
        std::shared_ptr<Media::PixelMap> pix = pictureContent->GetBigPicture();
        if (pix == nullptr) {
            LOGE("Invalid object pixelMap");
            freeNotificationPictureContent(picture);
            return false;
        }
        auto native1 = FFIData::Create<Media::PixelMapImpl>(pix);
        if (native1 == nullptr) {
            LOGE("Invalid object pixelMap");
            freeNotificationPictureContent(picture);
            return false;
        }
        picture->picture = native1->GetID();
        // lockScreenPicture?: pixelMap
        picture->lockscreenPicture = -1;
        if (pictureContent->GetLockScreenPicture()) {
            std::shared_ptr<Media::PixelMap> pixx = pictureContent->GetLockScreenPicture();
            if (pixx == nullptr) {
                LOGE("Invalid object pixelMap");
                freeNotificationPictureContent(picture);
                return false;
            }
            auto native2 = FFIData::Create<Media::PixelMapImpl>(pixx);
            if (native2 == nullptr) {
                LOGE("Invalid object pixelMap");
                freeNotificationPictureContent(picture);
                return false;
            }
            picture->lockscreenPicture = native2->GetID();
        }
        return true;
    }

    static void freeNotificationMultiLineContent(CNotificationMultiLineContent* multiLine)
    {
        free(multiLine->title);
        free(multiLine->text);
        free(multiLine->additionalText);
        free(multiLine->briefText);
        free(multiLine->longTitle);
        if (multiLine->lines.head != nullptr) {
            for (int64_t i = 0; i < multiLine->lines.size; i++) {
                free(multiLine->lines.head[i]);
            }
            free(multiLine->lines.head);
            multiLine->lines.head = nullptr;
        }
        multiLine->title = nullptr;
        multiLine->text = nullptr;
        multiLine->additionalText = nullptr;
        multiLine->briefText = nullptr;
        multiLine->longTitle = nullptr;
    }

    bool SetNotificationMultiLineContent(
        NotificationBasicContent *basicContent,
        CNotificationMultiLineContent* multiLine)
    {
        if (basicContent == nullptr) {
            LOGE("basicContent is null");
            return false;
        }
        OHOS::Notification::NotificationMultiLineContent *multiLineContent =
            static_cast<OHOS::Notification::NotificationMultiLineContent *>(basicContent);
        if (multiLineContent == nullptr) {
            LOGE("multiLineContent is null");
            return false;
        }
        // title、text、additionalText?: string
        multiLine->title = MallocCString(multiLineContent->GetTitle());
        multiLine->text = MallocCString(multiLineContent->GetText());
        multiLine->additionalText = MallocCString(multiLineContent->GetAdditionalText());
        // briefText、longTitle: string
        multiLine->briefText = MallocCString(multiLineContent->GetBriefText());
        multiLine->longTitle = MallocCString(multiLineContent->GetExpandedTitle());
        // lines: Array<String>
        auto vecs = multiLineContent->GetAllLines();
        CArrString lines = { .head = nullptr, .size = 0 };
        lines.head = static_cast<char **>(malloc(sizeof(char *) * vecs.size()));
        lines.size = static_cast<int64_t>(vecs.size());
        if (lines.head == nullptr) {
            LOGE("multiLineContent lines malloc failed");
            freeNotificationMultiLineContent(multiLine);
            return false;
        }
        int i = 0 ;
        for (auto vec : vecs) {
            lines.head[i++] = MallocCString(vec);
        }
        multiLine->lines = lines;
        // lockScreenPicture?: pixelMap
        multiLine->lockscreenPicture = -1;
        if (multiLineContent->GetLockScreenPicture()) {
            std::shared_ptr<Media::PixelMap> pix = multiLineContent->GetLockScreenPicture();
            if (pix == nullptr) {
                LOGE("Invalid object pixelMap");
                freeNotificationMultiLineContent(multiLine);
                return false;
            }
            auto native2 = FFIData::Create<Media::PixelMapImpl>(pix);
            if (native2 == nullptr) {
                LOGE("Invalid object pixelMap");
                freeNotificationMultiLineContent(multiLine);
                return false;
            }
            multiLine->lockscreenPicture = native2->GetID();
        }
        return true;
    }

    bool SetCapsule(const NotificationCapsule &capsule, CNotificationCapsule &cCapsule)
    {
        // title: string
        cCapsule.title = MallocCString(capsule.GetTitle());
        // backgroundColor: string
        cCapsule.backgroundColor = MallocCString(capsule.GetBackgroundColor());
        // icon?: image.PixelMap
        std::shared_ptr<Media::PixelMap> icon = capsule.GetIcon();
        if (icon) {
            auto native = FFIData::Create<Media::PixelMapImpl>(icon);
            if (native == nullptr) {
                free(cCapsule.title);
                free(cCapsule.backgroundColor);
                cCapsule.title = nullptr;
                cCapsule.backgroundColor = nullptr;
                LOGE("Invalid object pixelMap of icon");
                return false;
            }
            cCapsule.icon = native->GetID();
        }
        return true;
    }

    bool SetButton(const NotificationLocalLiveViewButton &button, CNotificationButton &cButton)
    {
        // buttonNames: Array<String>
        auto vecs = button.GetAllButtonNames();
        CArrString names = { .head = nullptr, .size = 0 };
        names.head = static_cast<char **>(malloc(sizeof(char *) * vecs.size()));
        names.size = static_cast<int64_t>(vecs.size());
        if (names.head == nullptr) {
            LOGE("NotificationButton names malloc failed");
            return false;
        }
        int i = 0;
        for (auto vec : vecs) {
            names.head[i++] = MallocCString(vec);
        }
        cButton.names = names;

        // buttonIcons: Array<PixelMap>
        int iconCount = 0;
        std::vector<std::shared_ptr<Media::PixelMap>> iconsVec = button.GetAllButtonIcons();
        CArrI64 icons = { .head = nullptr, .size = iconsVec.size() };
        for (auto vec : iconsVec) {
            if (!vec) {
                continue;
            }
            // buttonIcon
            auto native = FFIData::Create<Media::PixelMapImpl>(vec);
            if (native == nullptr) {
                LOGE("Invalid object pixelMap of buttonIcons.");
                return false; // memory free at cj
            }
            icons.head[iconCount++] = native->GetID();
        }
        cButton.icons = icons;
        return true;
    }

    bool SetNotificationLocalLiveViewContentDetailed(NotificationLocalLiveViewContent *localLiveViewContent,
        CNotificationSystemLiveViewContent* systemLiveView)
    {
        // capsule: NotificationCapsule
        CNotificationCapsule capsule = {
            .title = nullptr,
            .icon = -1,
            .backgroundColor = nullptr
        };
        if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE)) {
            if (!SetCapsule(localLiveViewContent->GetCapsule(), capsule)) {
                LOGE("SetCapsule call failed");
                return false;
            }
        }
        systemLiveView->capsule = capsule;

        // button: NotificationLocalLiveViewButton
        CNotificationButton cButton = {
            .names = { .head = nullptr, .size = 0 },
            .icons = { .head = nullptr, .size = 0 }
        };
        if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON)) {
            if (!SetButton(localLiveViewContent->GetButton(), cButton)) {
                LOGE("SetButton call failed");
                return false;
            }
        }
        systemLiveView->button = cButton;

        // progress: NotificationProgress
        CNotificationProgress cProgress;
        if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::PROGRESS)) {
            NotificationProgress progress = localLiveViewContent->GetProgress();
            cProgress.maxValue = progress.GetMaxValue();
            cProgress.currentValue = progress.GetCurrentValue();
            cProgress.isPercentage = progress.GetIsPercentage();
        }
        systemLiveView->progress = cProgress;

        // time: NotificationTime
        CNotificationTime cTime;
        if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::TIME)) {
            NotificationTime time = localLiveViewContent->GetTime();
            bool flag = localLiveViewContent->isFlagExist(
                NotificationLocalLiveViewContent::LiveViewContentInner::INITIAL_TIME);
            cTime.initialTime = flag ? time.GetInitialTime() : 0;
            cTime.isCountDown = time.GetIsCountDown();
            cTime.isPaused = time.GetIsPaused();
            cTime.isInTitle = time.GetIsInTitle();
        }
        systemLiveView->time = cTime;

        return true;
    }

    bool SetNotificationLocalLiveViewContent(NotificationBasicContent *basicContent,
        CNotificationSystemLiveViewContent* systemLiveView)
    {
        if (basicContent == nullptr) {
            LOGE("basicContent is null.");
            return false;
        }
        if (systemLiveView == nullptr) {
            LOGE("malloc CNotificationSystemLiveViewContent failed, systemLiveView is null");
            return false;
        }
        OHOS::Notification::NotificationLocalLiveViewContent *localLiveViewContent =
            static_cast<OHOS::Notification::NotificationLocalLiveViewContent *>(basicContent);
        if (localLiveViewContent == nullptr) {
            LOGE("localLiveViewContent is null");
            return false;
        }

        // title, text, additionalText?
        systemLiveView->title = MallocCString(localLiveViewContent->GetTitle());
        systemLiveView->text = MallocCString(localLiveViewContent->GetText());
        systemLiveView->additionalText = MallocCString(localLiveViewContent->GetAdditionalText());
        // typeCode: int32_t
        systemLiveView->typeCode = localLiveViewContent->GetType();
        
        if (!SetNotificationLocalLiveViewContentDetailed(localLiveViewContent, systemLiveView)) {
            LOGE("SetNotificationLocalLiveViewContentDetail call failed");
            return false;
        }

        // lockScreenPicture?: pixelMap
        systemLiveView->lockscreenPicture = -1;
        if (localLiveViewContent->GetLockScreenPicture()) {
            std::shared_ptr<Media::PixelMap> pix = localLiveViewContent->GetLockScreenPicture();
            if (pix == nullptr) {
                LOGE("Invalid object pixelMap");
                return false;
            }
            auto native2 = FFIData::Create<Media::PixelMapImpl>(pix);
            if (native2 == nullptr) {
                LOGE("Invalid object pixelMap");
                return false;
            }
            systemLiveView->lockscreenPicture = native2->GetID();
        }
        return true;
    }

    bool SetNotificationContentDetailed(const ContentType &type,
        const std::shared_ptr<NotificationContent> &content, CNotificationContent &notificationContent)
    {
        bool ret = false;
        std::shared_ptr<NotificationBasicContent> basicContent = content->GetNotificationContent();
        if (basicContent == nullptr) {
            LOGE("content is null");
            return ret;
        }
        switch (type) {
            case ContentType::NOTIFICATION_CONTENT_BASIC_TEXT: // normal?: NotificationBasicContent
                notificationContent.normal =
                    static_cast<CNotificationBasicContent *>(malloc(sizeof(CNotificationBasicContent)));
                ret = SetNotificationBasicContent(basicContent.get(), notificationContent.normal);
                break;
            case ContentType::NOTIFICATION_CONTENT_LONG_TEXT: // longText?: NotificationLongTextContent
                notificationContent.longText =
                    static_cast<CNotificationLongTextContent *>(malloc(sizeof(CNotificationLongTextContent)));
                ret = SetNotificationLongTextContent(basicContent.get(), notificationContent.longText);
                break;
            case ContentType::NOTIFICATION_CONTENT_PICTURE: // picture?: NotificationPictureContent
                notificationContent.picture =
                    static_cast<CNotificationPictureContent *>(malloc(sizeof(CNotificationPictureContent)));
                if (notificationContent.picture == nullptr) {
                    LOGE("SetNotificationContentDetailed malloc CNotificationPictureContent failed.");
                    return false;
                }
                ret = SetNotificationPictureContent(basicContent.get(), notificationContent.picture);
                break;
            case ContentType::NOTIFICATION_CONTENT_MULTILINE: // multiLine?: NotificationMultiLineContent
                notificationContent.multiLine =
                    static_cast<CNotificationMultiLineContent *>(malloc(sizeof(CNotificationMultiLineContent)));
                if (notificationContent.multiLine == nullptr) {
                    LOGE("SetNotificationContentDetailed malloc CNotificationMultiLineContent failed.");
                    return false;
                }
                ret = SetNotificationMultiLineContent(basicContent.get(), notificationContent.multiLine);
                break;
            case ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW: // systemLiveView?: NotificationLocalLiveViewContent
                notificationContent.systemLiveView =
                    static_cast<CNotificationSystemLiveViewContent *>(
                            malloc(sizeof(CNotificationSystemLiveViewContent)));
                ret = SetNotificationLocalLiveViewContent(basicContent.get(), notificationContent.systemLiveView);
                break;
            case ContentType::NOTIFICATION_CONTENT_LIVE_VIEW: // liveView?: NotificationLiveViewContent
                LOGE("ContentType::NOTIFICATION_CONTENT_LIVE_VIEW is not support");
            default:
                LOGE("ContentType is does not exist");
                return ret;
        }
        return ret;
    }

    bool SetNotificationContent(
        const std::shared_ptr<NotificationContent> &content,
        CNotificationContent &notificationContent)
    {
        // contentType: ContentType
        NotificationContent::Type type = content->GetContentType();
        ContentType outType = ContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
        if (!ContentTypeCToCJ(type, outType)) {
            return false;
        }
        notificationContent.notificationContentType = static_cast<int32_t>(outType);
        if (!SetNotificationContentDetailed(outType, content, notificationContent)) {
            LOGE("SetNotificationContentDetailed failed");
            return false;
        }
        return true;
    }

    bool SetNotificationFlags(
        const std::shared_ptr<NotificationFlags> &flags,
        CNotificationFlags &notificationFlags)
    {
        if (flags == nullptr) {
            LOGE("flags is null");
            return false;
        }
        notificationFlags.soundEnabled = static_cast<int32_t>(flags->IsSoundEnabled());
        notificationFlags.vibrationEnabled = static_cast<int32_t>(flags->IsVibrationEnabled());
        return true;
    }

    bool SetNotificationRequestByCustom(
        const NotificationRequest *request,
        CNotificationRequest &notificationRequest)
    {
        // content: NotificationContent
        std::shared_ptr<NotificationContent> content = request->GetContent();
        if (!content) {
            LOGE("content is nullptr");
            return false;
        }
        if (!SetNotificationContent(content, notificationRequest.notificationContent)) {
            LOGE("SetNotificationContent call failed");
            return false;
        }

        // readonly notificationFlags?: NotificationFlags
        std::shared_ptr<NotificationFlags> flags = request->GetFlags();
        if (flags) {
            if (!SetNotificationFlags(flags, notificationRequest.notificationFlags)) {
                LOGE("SetNotificationFlags call failed");
                return false;
            }
        }
        return true;
    }

    static void InitNotificationRequest(CNotificationRequest &notificationRequest)
    {
        notificationRequest.notificationContent = {
            .notificationContentType = 0,
            .normal = nullptr,
            .longText = nullptr,
            .multiLine = nullptr,
            .picture = nullptr
        };
        notificationRequest.label = nullptr;
        notificationRequest.creatorBundleName = nullptr;
        notificationRequest.groupName = nullptr;
        notificationRequest.distributedOption = nullptr;
        notificationRequest.hashCode = nullptr;
        notificationRequest.appMessageId = nullptr;
    }

    bool SetNotificationRequest(
        const NotificationRequest *request,
        CNotificationRequest &notificationRequest)
    {
        if (request == nullptr) {
            LOGE("request is nullptr");
            return false;
        }
        InitNotificationRequest(notificationRequest);
        SetNotificationRequestByString(request, notificationRequest);
        SetNotificationRequestByBool(request, notificationRequest);
        SetNotificationRequestByPixelMap(request, notificationRequest);
        if (!SetNotificationRequestByNumber(request, notificationRequest)) {
            LOGE("SetNotificationRequestByNumber failed");
            return false;
        }
        if (!SetNotificationRequestByCustom(request, notificationRequest)) {
            LOGE("SetNotificationRequestByCustom failed");
            return false;
        }
        return true;
    }
}
}
}