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
    void freeCArrString(CArrString& arrStr)
    {
        if (arrStr.head == nullptr) {
            return;
        }
        for (int64_t i = 0; i < arrStr.size; i++) {
            free(arrStr.head[i]);
        }
        free(arrStr.head);
        arrStr.head = nullptr;
        arrStr.size = 0;
    }

    bool GetNotificationSupportDisplayDevicesV2(
        CDistributedOptionsV2* distributedOption,
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

    bool GetNotificationSupportOperateDevicesV2(
        CDistributedOptionsV2* distributedOption,
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

    bool GetNotificationRequestDistributedOptionsV2(
        CDistributedOptionsV2* distributedOption,
        NotificationRequest request)
    {
        if (distributedOption != nullptr) {
            // isDistributed?: boolean
            request.SetDistributed(distributedOption->isDistributed);

            // supportDisplayDevices?: Array<string>
            if (!GetNotificationSupportDisplayDevicesV2(distributedOption, request)) {
                return false;
            }

            // supportOperateDevices?: Array<string>
            if (!GetNotificationSupportOperateDevicesV2(distributedOption, request)) {
                return false;
            }
        }
        return true;
    }

    bool GetNotificationRequestByNumberV2(CNotificationRequestV2 cjRequest, NotificationRequest &request)
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

    bool GetNotificationRequestByStringV2(CNotificationRequestV2 cjRequest, NotificationRequest &request)
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

    bool GetNotificationRequestByBoolV2(CNotificationRequestV2 cjRequest, NotificationRequest &request)
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

    bool GetNotificationRequestByCustomV2(CNotificationRequestV2 cjRequest, NotificationRequest &request)
    {
        // content: NotificationContent
        if (!GetNotificationContentV2(cjRequest.notificationContent, request)) {
            return false;
        }
        // slotType?: notification.SlotTypeV2
        if (!GetNotificationSlotTypeV2(cjRequest.notificationSlotType, request)) {
            return false;
        }
        // smallIcon?: image.PixelMap
        if (!GetNotificationSmallIconV2(cjRequest.smallIcon, request)) {
            return false;
        }
        // largeIcon?: image.PixelMap
        if (!GetNotificationLargeIconV2(cjRequest.largeIcon, request)) {
            return false;
        }
        // distributedOption?:DistributedOptions
        if (!GetNotificationRequestDistributedOptionsV2(cjRequest.distributedOption, request)) {
            return false;
        }

        return true;
    }

    bool GetNotificationBasicContentDetailedV2(CNotificationBasicContentV2* contentResult,
        std::shared_ptr<NotificationBasicContent> basicContent)
    {
        char str[SHORT_STR_SIZE] = {0};
        char long_str[LONG_STR_SIZE] = {0};
        // title: String
        if (strcpy_s(str, SHORT_STR_SIZE, contentResult->title) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property title is empty");
            return false;
        }
        basicContent->SetTitle(std::string(str));
        // text: String
        if (strcpy_s(long_str, LONG_STR_SIZE, contentResult->text) != EOK) {
            return false;
        }
        if (strlen(long_str) == 0) {
            LOGE("Property text is empty");
            return false;
        }
        basicContent->SetText(std::string(long_str));
        // additionalText: string
        if (strcpy_s(long_str, LONG_STR_SIZE, contentResult->additionalText) != EOK) {
            return false;
        }
        basicContent->SetAdditionalText(std::string(long_str));
        
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

    bool GetNotificationBasicContentV2(CNotificationBasicContentV2* contentResult, NotificationRequest &request)
    {
        std::shared_ptr<NotificationNormalContent> normalContent = std::make_shared<NotificationNormalContent>();
        if (normalContent == nullptr) {
            LOGE("normalContent is null");
            return false;
        }

        if (!GetNotificationBasicContentDetailedV2(contentResult, normalContent)) {
            return false;
        }
        request.SetContent(std::make_shared<NotificationContent>(normalContent));
        return true;
    }

    bool GetNotificationLongTextContentDetailedV2(
        CNotificationLongTextContentV2* contentResult,
        std::shared_ptr<NotificationLongTextContent> &longContent)
    {
        char str[SHORT_STR_SIZE] = {0};
        char long_str[LONG_STR_SIZE] = {0};

        std::shared_ptr<CNotificationBasicContentV2> tempContent = std::make_shared<CNotificationBasicContentV2>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        tempContent->lockscreenPicture = contentResult->lockscreenPicture;
        if (!GetNotificationBasicContentDetailedV2(tempContent.get(), longContent)) {
            return false;
        }
        
        // longText: String
        if (strcpy_s(long_str, LONG_STR_SIZE, contentResult->longText) != EOK) {
            return false;
        }
        if (strlen(long_str) == 0) {
            LOGE("Property longText is empty");
            return false;
        }
        longContent->SetLongText(std::string(long_str));

        // briefText: String
        if (strcpy_s(str, SHORT_STR_SIZE, contentResult->briefText) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property briefText is empty");
            return false;
        }
        longContent->SetBriefText(std::string(str));

        // expandedTitle: String
        if (strcpy_s(str, SHORT_STR_SIZE, contentResult->expandedTitle) != EOK) {
            return false;
        }
        if (strlen(str) == 0) {
            LOGE("Property expandedTitle is empty");
            return false;
        }
        longContent->SetExpandedTitle(std::string(str));

        return true;
    }

    bool GetNotificationLongTextContentV2(
        CNotificationLongTextContentV2* contentResult,
        NotificationRequest &request)
    {
        std::shared_ptr<OHOS::Notification::NotificationLongTextContent> longContent =
        std::make_shared<OHOS::Notification::NotificationLongTextContent>();
        if (longContent == nullptr) {
            LOGE("longContent is null");
            return false;
        }
        if (!GetNotificationLongTextContentDetailedV2(contentResult, longContent)) {
            return false;
        }
        
        request.SetContent(std::make_shared<NotificationContent>(longContent));
        return true;
    }

    bool GetNotificationPictureContentDetailedV2(
        CNotificationPictureContentV2* contentResult,
        std::shared_ptr<NotificationPictureContent> &pictureContent)
    {
        char str[SHORT_STR_SIZE] = {0};
        char long_str[LONG_STR_SIZE] = {0};

        std::shared_ptr<CNotificationBasicContentV2> tempContent = std::make_shared<CNotificationBasicContentV2>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        tempContent->lockscreenPicture = contentResult->lockscreenPicture;
        if (!GetNotificationBasicContentDetailedV2(tempContent.get(), pictureContent)) {
            return false;
        }

        // briefText: String
        if (strcpy_s(str, SHORT_STR_SIZE, contentResult->briefText) != EOK) {
            return false;
        }
        if (std::strlen(str) == 0) {
            LOGE("Property briefText is empty");
            return false;
        }
        pictureContent->SetBriefText(std::string(str));

        // expandedTitle: String
        if (strcpy_s(long_str, LONG_STR_SIZE, contentResult->expandedTitle) != EOK) {
            return false;
        }
        if (std::strlen(long_str) == 0) {
            LOGE("Property expandedTitle is empty");
            return false;
        }
        pictureContent->SetExpandedTitle(std::string(long_str));

        // picture: image.PixelMap
        auto pixelMap = FFIData::GetData<Media::PixelMapImpl>(contentResult->picture);
        if (pixelMap == nullptr) {
            LOGE("Invalid object pixelMap");
            return false;
        }
        pictureContent->SetBigPicture(pixelMap->GetRealPixelMap());

        return true;
    }

    bool GetNotificationPictureContentV2(
        CNotificationPictureContentV2* contentResult,
        NotificationRequest &request)
    {
        std::shared_ptr<OHOS::Notification::NotificationPictureContent> pictureContent =
        std::make_shared<OHOS::Notification::NotificationPictureContent>();
        if (pictureContent == nullptr) {
            LOGE("pictureContent is null");
            return false;
        }

        if (!GetNotificationPictureContentDetailedV2(contentResult, pictureContent)) {
            return false;
        }

        request.SetContent(std::make_shared<NotificationContent>(pictureContent));
        return true;
    }

    bool GetNotificationMultiLineContentLinesV2(
        CNotificationMultiLineContentV2* result,
        std::shared_ptr<OHOS::Notification::NotificationMultiLineContent> &multiLineContent)
    {
        char str[SHORT_STR_SIZE] = {0};
        int64_t length = result->lines.size;
        if (length == 0) {
            LOGE("The array is empty.");
            return false;
        }
        for (int64_t i = 0; i < length; i++) {
            if (strcpy_s(str, SHORT_STR_SIZE, result->lines.head[i]) != EOK) {
                return false;
            }
            multiLineContent->AddSingleLine(std::string(str));
        }
        return true;
    }

    bool GetNotificationMultiLineContentV2(
        CNotificationMultiLineContentV2* contentResult,
        NotificationRequest &request)
    {
        char str[SHORT_STR_SIZE] = {0};

        std::shared_ptr<OHOS::Notification::NotificationMultiLineContent> multiLineContent =
        std::make_shared<OHOS::Notification::NotificationMultiLineContent>();
        if (multiLineContent == nullptr) {
            LOGE("multiLineContent is null");
            return false;
        }

        std::shared_ptr<CNotificationBasicContentV2> tempContent = std::make_shared<CNotificationBasicContentV2>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        tempContent->lockscreenPicture = contentResult->lockscreenPicture;
        if (!GetNotificationBasicContentDetailedV2(tempContent.get(), multiLineContent)) {
            return false;
        }

        // briefText: String
        if (strcpy_s(str, SHORT_STR_SIZE, contentResult->briefText) != EOK) {
            return false;
        }
        if (std::strlen(str) == 0) {
            LOGE("Property briefText is empty");
            return false;
        }
        multiLineContent->SetBriefText(std::string(str));

        // longTitle: String
        if (strcpy_s(str, LONG_STR_SIZE, contentResult->longTitle) != EOK) {
            return false;
        }
        if (std::strlen(str) == 0) {
            LOGE("Property longTitle is empty");
            return false;
        }
        multiLineContent->SetExpandedTitle(std::string(str));

        // lines: Array<String>
        if (!GetNotificationMultiLineContentLinesV2(contentResult, multiLineContent)) {
            return false;
        }

        request.SetContent(std::make_shared<NotificationContent>(multiLineContent));
        return true;
    }

    bool GetNotificationLocalLiveViewCapsuleV2(CNotificationSystemLiveViewContentV2* contentResult,
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

    bool GetNotificationLocalLiveViewButtonV2(CNotificationSystemLiveViewContentV2* contentResult,
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

    bool GetNotificationLocalLiveViewProgressV2(CNotificationSystemLiveViewContentV2* contentResult,
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

    bool GetNotificationLocalLiveViewTimeV2(CNotificationSystemLiveViewContentV2* contentResult,
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
    
    bool GetNotificationLocalLiveViewContentDetailedV2(CNotificationSystemLiveViewContentV2* contentResult,
        std::shared_ptr<NotificationLocalLiveViewContent> &content)
    {
        // title, text
        std::shared_ptr<CNotificationBasicContentV2> tempContent = std::make_shared<CNotificationBasicContentV2>();
        tempContent->title = contentResult->title;
        tempContent->text = contentResult->text;
        tempContent->additionalText = contentResult->additionalText;
        tempContent->lockscreenPicture = contentResult->lockscreenPicture;
        if (!GetNotificationBasicContentDetailedV2(tempContent.get(), content)) {
            LOGE("Basic content get fail.");
            return false;
        }

        // typeCode
        content->SetType(contentResult->typeCode);

        // capsule?
        if (!GetNotificationLocalLiveViewCapsuleV2(contentResult, content)) {
            LOGE("GetNotificationLocalLiveViewCapsuleV2 fail.");
            return false;
        }

        // button?
        if (!GetNotificationLocalLiveViewButtonV2(contentResult, content)) {
            LOGE("GetNotificationLocalLiveViewButtonV2 fail.");
            return false;
        }

        // progress?
        if (!GetNotificationLocalLiveViewProgressV2(contentResult, content)) {
            LOGE("GetNotificationLocalLiveViewProgressV2 fail.");
            return false;
        }

        // time?
        if (!GetNotificationLocalLiveViewTimeV2(contentResult, content)) {
            LOGE("GetNotificationLocalLiveViewTimeV2 fail.");
            return false;
        }

        return true;
    }

    bool GetNotificationLocalLiveViewContentV2(CNotificationSystemLiveViewContentV2* contentResult,
        NotificationRequest &request)
    {
        std::shared_ptr<NotificationLocalLiveViewContent> localLiveViewContent =
            std::make_shared<NotificationLocalLiveViewContent>();
        if (localLiveViewContent == nullptr) {
            LOGE("localLiveViewContent is null");
            return false;
        }

        if (!GetNotificationLocalLiveViewContentDetailedV2(contentResult, localLiveViewContent)) {
            return false;
        }

        request.SetContent(std::make_shared<NotificationContent>(localLiveViewContent));

        // set isOnGoing of live view true
        request.SetInProgress(true);
        return true;
    }

    bool SlotTypeCJToCV2(const SlotTypeV2 &inType, NotificationConstant::SlotType &outType)
    {
        switch (inType) {
            case SlotTypeV2::SOCIAL_COMMUNICATION:
                outType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
                break;
            case SlotTypeV2::SERVICE_INFORMATION:
                outType = NotificationConstant::SlotType::SERVICE_REMINDER;
                break;
            case SlotTypeV2::CONTENT_INFORMATION:
                outType = NotificationConstant::SlotType::CONTENT_INFORMATION;
                break;
            case SlotTypeV2::LIVE_VIEW:
                outType = NotificationConstant::SlotType::LIVE_VIEW;
                break;
            case SlotTypeV2::CUSTOMER_SERVICE:
                outType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
                break;
            case SlotTypeV2::UNKNOWN_TYPE:
            case SlotTypeV2::OTHER_TYPES:
                outType = NotificationConstant::SlotType::OTHER;
                break;
            default:
                LOGE("SlotType %{public}d is an invalid value", inType);
                return false;
        }
        return true;
    }

    bool SlotTypeCToCJV2(const NotificationConstant::SlotType &inType, SlotTypeV2 &outType)
    {
        switch (inType) {
            case NotificationConstant::SlotType::CUSTOM:
                outType = SlotTypeV2::UNKNOWN_TYPE;
                break;
            case NotificationConstant::SlotType::SOCIAL_COMMUNICATION:
                outType = SlotTypeV2::SOCIAL_COMMUNICATION;
                break;
            case NotificationConstant::SlotType::SERVICE_REMINDER:
                outType = SlotTypeV2::SERVICE_INFORMATION;
                break;
            case NotificationConstant::SlotType::CONTENT_INFORMATION:
                outType = SlotTypeV2::CONTENT_INFORMATION;
                break;
            case NotificationConstant::SlotType::LIVE_VIEW:
                outType = SlotTypeV2::LIVE_VIEW;
                break;
            case NotificationConstant::SlotType::CUSTOMER_SERVICE:
                outType = SlotTypeV2::CUSTOMER_SERVICE;
                break;
            case NotificationConstant::SlotType::OTHER:
                outType = SlotTypeV2::OTHER_TYPES;
                break;
            default:
                LOGE("SlotType %{public}d is an invalid value", inType);
                return false;
        }
        return true;
    }

    bool SlotLevelCToCJV2(const NotificationSlot::NotificationLevel &inLevel, SlotLevel &outLevel)
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

    bool ContentTypeCJToCV2(const ContentTypeV2 &inType, NotificationContent::Type &outType)
    {
        switch (inType) {
            case ContentTypeV2::NOTIFICATION_CONTENT_BASIC_TEXT:
                outType = NotificationContent::Type::BASIC_TEXT;
                break;
            case ContentTypeV2::NOTIFICATION_CONTENT_LONG_TEXT:
                outType = NotificationContent::Type::LONG_TEXT;
                break;
            case ContentTypeV2::NOTIFICATION_CONTENT_MULTILINE:
                outType = NotificationContent::Type::MULTILINE;
                break;
            case ContentTypeV2::NOTIFICATION_CONTENT_PICTURE:
                outType = NotificationContent::Type::PICTURE;
                break;
            case ContentTypeV2::NOTIFICATION_CONTENT_CONVERSATION:
                outType = NotificationContent::Type::CONVERSATION;
                break;
            case ContentTypeV2::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW:
                outType = NotificationContent::Type::LOCAL_LIVE_VIEW;
                break;
            case ContentTypeV2::NOTIFICATION_CONTENT_LIVE_VIEW:
                outType = NotificationContent::Type::LIVE_VIEW;
                break;
            default:
                LOGE("ContentType %{public}d is an invalid value", inType);
                return false;
        }
        return true;
    }

    bool ContentTypeCToCJV2(const NotificationContent::Type &inType, ContentTypeV2 &outType)
    {
        switch (inType) {
            case NotificationContent::Type::BASIC_TEXT:
                outType = ContentTypeV2::NOTIFICATION_CONTENT_BASIC_TEXT;
                break;
            case NotificationContent::Type::LONG_TEXT:
                outType = ContentTypeV2::NOTIFICATION_CONTENT_LONG_TEXT;
                break;
            case NotificationContent::Type::MULTILINE:
                outType = ContentTypeV2::NOTIFICATION_CONTENT_MULTILINE;
                break;
            case NotificationContent::Type::PICTURE:
                outType = ContentTypeV2::NOTIFICATION_CONTENT_PICTURE;
                break;
            case NotificationContent::Type::CONVERSATION:
                outType = ContentTypeV2::NOTIFICATION_CONTENT_CONVERSATION;
                break;
            case NotificationContent::Type::LOCAL_LIVE_VIEW:
                outType = ContentTypeV2::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW;
                break;
            case NotificationContent::Type::LIVE_VIEW:
                outType = ContentTypeV2::NOTIFICATION_CONTENT_LIVE_VIEW;
                break;
            default:
                LOGE("ContentType %{public}d is an invalid value", inType);
                return false;
        }
        return true;
    }

    bool GetNotificationSlotTypeV2(int32_t slotType, NotificationRequest &request)
    {
        NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
        if (!SlotTypeCJToCV2(SlotTypeV2(slotType), outType)) {
            return false;
        }
        request.SetSlotType(outType);
        return true;
    }

    bool GetNotificationSmallIconV2(int64_t smallIcon, NotificationRequest &request)
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

    bool GetNotificationLargeIconV2(int64_t largeIcon, NotificationRequest &request)
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

    bool GetNotificationContentV2(CNotificationContentV2 &content, NotificationRequest &request)
    {
        NotificationContent::Type outType = NotificationContent::Type::NONE;
        if (!ContentTypeCJToCV2(ContentTypeV2(content.notificationContentType), outType)) {
            return false;
        }
        switch (outType) {
            case NotificationContent::Type::BASIC_TEXT:
                if (content.normal == nullptr || !GetNotificationBasicContentV2(content.normal, request)) {
                    return false;
                }
                break;
            case NotificationContent::Type::LONG_TEXT:
                if (content.longText == nullptr || !GetNotificationLongTextContentV2(content.longText, request)) {
                    return false;
                }
                break;
            case NotificationContent::Type::PICTURE:
                if (content.picture == nullptr || !GetNotificationPictureContentV2(content.picture, request)) {
                    return false;
                }
                break;
            case NotificationContent::Type::CONVERSATION:
                break;
            case NotificationContent::Type::MULTILINE:
                if (content.multiLine == nullptr || !GetNotificationMultiLineContentV2(content.multiLine, request)) {
                    return false;
                }
                break;
            case NotificationContent::Type::LOCAL_LIVE_VIEW:
                if (content.systemLiveView == nullptr ||
                    !GetNotificationLocalLiveViewContentV2(content.systemLiveView, request)) {
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

    bool SetNotificationSlotV2(const NotificationSlot &slot, CNotificationSlotV2 &notificationSlot)
    {
        // type: SlotTypeV2
        SlotTypeV2 outType = SlotTypeV2::UNKNOWN_TYPE;
        if (!SlotTypeCToCJV2(slot.GetType(), outType)) {
            LOGE("SetNotificationSlotV2 SlotTypeCToCJV2 failed.");
            return false;
        }
        // level?: int32_t
        SlotLevel outLevel = SlotLevel::LEVEL_NONE;
        if (!SlotLevelCToCJV2(slot.GetLevel(), outLevel)) {
            LOGE("SetNotificationSlotV2 SlotLevelCToCJV2 failed.");
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
                LOGE("SetNotificationSlotV2 malloc vibrationValues.head failed.");
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

    void SetNotificationRequestByStringV2(
        const NotificationRequest *request,
        CNotificationRequestV2 &notificationRequest)
    {
        // label?: string
        notificationRequest.label = MallocCString(request->GetLabel());

        // groupName?: string
        notificationRequest.groupName = MallocCString(request->GetGroupName());

        // readonly creatorBundleName?: string
        notificationRequest.creatorBundleName = MallocCString(request->GetCreatorBundleName());
    }

    bool SetNotificationRequestByNumberV2(
        const NotificationRequest *request,
        CNotificationRequestV2 &notificationRequest)
    {
        // id?: int32_t
        notificationRequest.id = request->GetNotificationId();

        // slotType?: SlotTypeV2
        SlotTypeV2 outType = SlotTypeV2::UNKNOWN_TYPE;
        if (!SlotTypeCToCJV2(request->GetSlotType(), outType)) {
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

    void SetNotificationRequestByBoolV2(
        const NotificationRequest *request,
        CNotificationRequestV2 &notificationRequest)
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

    void SetNotificationRequestByPixelMapV2(
        const NotificationRequest *request,
        CNotificationRequestV2 &notificationRequest)
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

    static void freeNotificationBasicContent(CNotificationBasicContentV2* normal)
    {
        free(normal->title);
        free(normal->text);
        free(normal->additionalText);
        normal->title = nullptr;
        normal->text = nullptr;
        normal->additionalText = nullptr;
    }

    bool SetNotificationBasicContentV2(
        const NotificationBasicContent *basicContent,
        CNotificationBasicContentV2* normal)
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

    static void freeNotificationLongTextContent(CNotificationLongTextContentV2* longText)
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

    bool SetNotificationLongTextContentV2(
        NotificationBasicContent *basicContent,
        CNotificationLongTextContentV2* longText)
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

    static void freeNotificationPictureContent(CNotificationPictureContentV2* picture)
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

    bool SetNotificationPictureContentV2(NotificationBasicContent *basicContent,
        CNotificationPictureContentV2* picture)
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

    static void freeNotificationMultiLineContent(CNotificationMultiLineContentV2* multiLine)
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

    bool SetNotificationMultiLineContentV2(
        NotificationBasicContent *basicContent,
        CNotificationMultiLineContentV2* multiLine)
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

    bool SetCapsuleV2(const NotificationCapsule &capsule, CNotificationCapsuleV2 &cCapsule)
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

    bool SetButtonV2(const NotificationLocalLiveViewButton &button, CNotificationButtonV2 &cButton)
    {
        // buttonNames: Array<String>
        auto vecs = button.GetAllButtonNames();
        CArrString names = { .head = nullptr, .size = 0 };
        if (vecs.size() > 0) {
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
        }
        cButton.names = names;

        // buttonIcons: Array<PixelMap>
        int iconCount = 0;
        std::vector<std::shared_ptr<Media::PixelMap>> iconsVec = button.GetAllButtonIcons();
        CArrI64 icons = { .head = nullptr, .size = 0 };
        if (iconsVec.size()) {
            icons.head = static_cast<int64_t *>(malloc(sizeof(int64_t) * iconsVec.size()));
            if (icons.head == nullptr) {
                LOGE("NotificationButton icons malloc failed");
                return false;
            }
            for (auto vec : iconsVec) {
                // buttonIcon
                auto native = FFIData::Create<Media::PixelMapImpl>(vec);
                if (native == nullptr) {
                    LOGE("Invalid object pixelMap of buttonIcons.");
                    free(icons.head);
                    freeCArrString(cButton.names);
                    return false;
                }
                icons.head[iconCount++] = native->GetID();
            }
        }
        icons.size = static_cast<int64_t>(iconsVec.size());
        cButton.icons = icons;
        return true;
    }

    bool SetNotificationLocalLiveViewContentDetailedV2(NotificationLocalLiveViewContent *localLiveViewContent,
        CNotificationSystemLiveViewContentV2* systemLiveView)
    {
        // capsule: NotificationCapsule
        CNotificationCapsuleV2 capsule = {
            .title = nullptr,
            .icon = -1,
            .backgroundColor = nullptr
        };
        if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE)) {
            if (!SetCapsuleV2(localLiveViewContent->GetCapsule(), capsule)) {
                LOGE("SetCapsuleV2 call failed");
                return false;
            }
        }
        systemLiveView->capsule = capsule;

        // button: NotificationLocalLiveViewButton
        CNotificationButtonV2 cButton = {
            .names = { .head = nullptr, .size = 0 },
            .icons = { .head = nullptr, .size = 0 }
        };
        if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON)) {
            if (!SetButtonV2(localLiveViewContent->GetButton(), cButton)) {
                LOGE("SetButtonV2 call failed");
                return false;
            }
        }
        systemLiveView->button = cButton;

        // progress: NotificationProgress
        CNotificationProgressV2 cProgress;
        if (localLiveViewContent->isFlagExist(NotificationLocalLiveViewContent::LiveViewContentInner::PROGRESS)) {
            NotificationProgress progress = localLiveViewContent->GetProgress();
            cProgress.maxValue = progress.GetMaxValue();
            cProgress.currentValue = progress.GetCurrentValue();
            cProgress.isPercentage = progress.GetIsPercentage();
        }
        systemLiveView->progress = cProgress;

        // time: NotificationTime
        CNotificationTimeV2 cTime;
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

    bool SetNotificationLocalLiveViewContentV2(NotificationBasicContent *basicContent,
        CNotificationSystemLiveViewContentV2* systemLiveView)
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
        
        if (!SetNotificationLocalLiveViewContentDetailedV2(localLiveViewContent, systemLiveView)) {
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

    bool SetNotificationContentDetailedV2(const ContentTypeV2 &type,
        const std::shared_ptr<NotificationContent> &content, CNotificationContentV2 &notificationContent)
    {
        bool ret = false;
        std::shared_ptr<NotificationBasicContent> basicContent = content->GetNotificationContent();
        if (basicContent == nullptr) {
            LOGE("content is null");
            return ret;
        }
        switch (type) {
            // normal?: NotificationBasicContent
            case ContentTypeV2::NOTIFICATION_CONTENT_BASIC_TEXT:
                notificationContent.normal =
                    static_cast<CNotificationBasicContentV2 *>(malloc(sizeof(CNotificationBasicContentV2)));
                ret = SetNotificationBasicContentV2(basicContent.get(), notificationContent.normal);
                break;
            // longText?: NotificationLongTextContent
            case ContentTypeV2::NOTIFICATION_CONTENT_LONG_TEXT:
                notificationContent.longText =
                    static_cast<CNotificationLongTextContentV2 *>(malloc(sizeof(CNotificationLongTextContentV2)));
                ret = SetNotificationLongTextContentV2(basicContent.get(), notificationContent.longText);
                break;
            // picture?: NotificationPictureContent
            case ContentTypeV2::NOTIFICATION_CONTENT_PICTURE:
                notificationContent.picture =
                    static_cast<CNotificationPictureContentV2 *>(malloc(sizeof(CNotificationPictureContentV2)));
                if (notificationContent.picture == nullptr) {
                    LOGE("SetNotificationContentDetailedV2 malloc CNotificationPictureContent failed.");
                    return false;
                }
                ret = SetNotificationPictureContentV2(basicContent.get(), notificationContent.picture);
                break;
            // multiLine?: NotificationMultiLineContent
            case ContentTypeV2::NOTIFICATION_CONTENT_MULTILINE:
                notificationContent.multiLine =
                    static_cast<CNotificationMultiLineContentV2 *>(malloc(sizeof(CNotificationMultiLineContentV2)));
                if (notificationContent.multiLine == nullptr) {
                    LOGE("SetNotificationContentDetailedV2 malloc CNotificationMultiLineContent failed.");
                    return false;
                }
                ret = SetNotificationMultiLineContentV2(basicContent.get(), notificationContent.multiLine);
                break;
            // systemLiveView?: NotificationLocalLiveViewContent
            case ContentTypeV2::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW:
                notificationContent.systemLiveView = static_cast<CNotificationSystemLiveViewContentV2 *>(
                            malloc(sizeof(CNotificationSystemLiveViewContentV2)));
                ret = SetNotificationLocalLiveViewContentV2(basicContent.get(), notificationContent.systemLiveView);
                break;
            // liveView?: NotificationLiveViewContent
            case ContentTypeV2::NOTIFICATION_CONTENT_LIVE_VIEW:
                LOGE("ContentType::NOTIFICATION_CONTENT_LIVE_VIEW is not support");
                break;
            default:
                LOGE("ContentType is does not exist");
                return ret;
        }
        return ret;
    }

    bool SetNotificationContentV2(
        const std::shared_ptr<NotificationContent> &content,
        CNotificationContentV2 &notificationContent)
    {
        // contentType: ContentTypeV2
        NotificationContent::Type type = content->GetContentType();
        ContentTypeV2 outType = ContentTypeV2::NOTIFICATION_CONTENT_BASIC_TEXT;
        if (!ContentTypeCToCJV2(type, outType)) {
            return false;
        }
        notificationContent.notificationContentType = static_cast<int32_t>(outType);
        if (!SetNotificationContentDetailedV2(outType, content, notificationContent)) {
            LOGE("SetNotificationContentDetailedV2 failed");
            return false;
        }
        return true;
    }

    bool SetNotificationFlagsV2(
        const std::shared_ptr<NotificationFlags> &flags,
        CNotificationFlagsV2 &notificationFlags)
    {
        if (flags == nullptr) {
            LOGE("flags is null");
            return false;
        }
        notificationFlags.soundEnabled = static_cast<int32_t>(flags->IsSoundEnabled());
        notificationFlags.vibrationEnabled = static_cast<int32_t>(flags->IsVibrationEnabled());
        return true;
    }

    bool SetNotificationRequestByCustomV2(
        const NotificationRequest *request,
        CNotificationRequestV2 &notificationRequest)
    {
        // content: NotificationContent
        std::shared_ptr<NotificationContent> content = request->GetContent();
        if (!content) {
            LOGE("content is nullptr");
            return false;
        }
        if (!SetNotificationContentV2(content, notificationRequest.notificationContent)) {
            LOGE("SetNotificationContentV2 call failed");
            return false;
        }

        // readonly notificationFlags?: NotificationFlags
        std::shared_ptr<NotificationFlags> flags = request->GetFlags();
        if (flags) {
            if (!SetNotificationFlagsV2(flags, notificationRequest.notificationFlags)) {
                LOGE("SetNotificationFlagsV2 call failed");
                return false;
            }
        }
        return true;
    }

    static void InitNotificationRequest(CNotificationRequestV2 &notificationRequest)
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

    bool SetNotificationRequestV2(
        const NotificationRequest *request,
        CNotificationRequestV2 &notificationRequest)
    {
        if (request == nullptr) {
            LOGE("request is nullptr");
            return false;
        }
        InitNotificationRequest(notificationRequest);
        SetNotificationRequestByStringV2(request, notificationRequest);
        SetNotificationRequestByBoolV2(request, notificationRequest);
        SetNotificationRequestByPixelMapV2(request, notificationRequest);
        if (!SetNotificationRequestByNumberV2(request, notificationRequest)) {
            LOGE("SetNotificationRequestByNumberV2 failed");
            return false;
        }
        if (!SetNotificationRequestByCustomV2(request, notificationRequest)) {
            LOGE("SetNotificationRequestByCustomV2 failed");
            return false;
        }
        return true;
    }
}
}
}