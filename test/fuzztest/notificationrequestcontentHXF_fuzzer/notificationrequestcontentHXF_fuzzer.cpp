/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "notificationrequestcontentHXF_fuzzer.h"
#include "notification_content.h"
#include "notification_long_text_content.h"
#include "notification_multiline_content.h"
#include "notification_normal_content.h"
#include "notification_request.h"
#include "parcel.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>

namespace OHOS {
    namespace {
        constexpr uint8_t CONTENT_NORMAL_INDEX = 0;
        constexpr uint8_t CONTENT_MULTILINE_INDEX = 1;
        constexpr uint8_t CONTENT_TYPE_COUNT = 3;  // BASIC_TEXT, LONG_TEXT, MULTILINE
        constexpr size_t  COMMON_STRING_LEN  = 128;
        constexpr size_t  LONG_STRING_LEN    = 256;
        constexpr size_t  MAX_LONGTEXT_LEN   = 1100; // probe above the 1024-char limit
        constexpr uint8_t MAX_MULTILINES     = 9;    // probe above the 7-line limit
        constexpr uint8_t SLOT_TYPE_NUM      = 8;    // SlotType enum range

        constexpr uint8_t MODULO_ZERO_FALLBACK = 0;

        template <typename ValueType, typename DivisorType>
        DivisorType ModuloByNonZero(ValueType value, DivisorType divisor)
        {
            if (divisor == static_cast<DivisorType>(MODULO_ZERO_FALLBACK)) {
                return static_cast<DivisorType>(MODULO_ZERO_FALLBACK);
            }
            return static_cast<DivisorType>(value % divisor);
        }
    }

    std::shared_ptr<Notification::NotificationContent> BuildBasicTextContent(
        FuzzedDataProvider *fdp,
        const std::string &title,
        const std::string &text,
        const std::string &additionalText)
    {
        Notification::NotificationNormalContent normalContent;
        normalContent.SetTitle(title);
        normalContent.SetText(text);
        normalContent.SetAdditionalText(additionalText);
        return std::make_shared<Notification::NotificationContent>(
            std::make_shared<Notification::NotificationNormalContent>(normalContent));
    }

    std::shared_ptr<Notification::NotificationContent> BuildLongTextContent(
        FuzzedDataProvider *fdp,
        const std::string &title,
        const std::string &text,
        const std::string &additionalText)
    {
        std::string longText     = fdp->ConsumeRandomLengthString(MAX_LONGTEXT_LEN);
        std::string expandedTitle = fdp->ConsumeRandomLengthString(LONG_STRING_LEN);
        std::string briefText    = fdp->ConsumeRandomLengthString(LONG_STRING_LEN);

        Notification::NotificationLongTextContent longTextContent;
        longTextContent.SetTitle(title);
        longTextContent.SetText(text);
        longTextContent.SetAdditionalText(additionalText);
        longTextContent.SetLongText(longText);
        longTextContent.SetExpandedTitle(expandedTitle);
        longTextContent.SetBriefText(briefText);
        return std::make_shared<Notification::NotificationContent>(
            std::make_shared<Notification::NotificationLongTextContent>(longTextContent));
    }

    std::shared_ptr<Notification::NotificationContent> BuildMultilineContent(
        FuzzedDataProvider *fdp,
        const std::string &title,
        const std::string &text,
        const std::string &additionalText)
    {
        uint8_t lineCount = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), MAX_MULTILINES);
        std::string expandedTitle = fdp->ConsumeRandomLengthString(LONG_STRING_LEN);
        std::string briefText     = fdp->ConsumeRandomLengthString(LONG_STRING_LEN);

        Notification::NotificationMultiLineContent multilineContent;
        multilineContent.SetTitle(title);
        multilineContent.SetText(text);
        multilineContent.SetAdditionalText(additionalText);
        multilineContent.SetExpandedTitle(expandedTitle);
        multilineContent.SetBriefText(briefText);
        for (uint8_t i = 0; i < lineCount; ++i) {
            multilineContent.AddSingleLine(fdp->ConsumeRandomLengthString(LONG_STRING_LEN));
        }
        return std::make_shared<Notification::NotificationContent>(
            std::make_shared<Notification::NotificationMultiLineContent>(multilineContent));
    }

    void TestRequestMarshalling(Notification::NotificationRequest &request)
    {
        Parcel parcel;
        if (request.Marshalling(parcel)) {
            Notification::NotificationRequest *restored =
                Notification::NotificationRequest::Unmarshalling(parcel);
            delete restored;
        }
    }

    void TestContentMarshalling(std::shared_ptr<Notification::NotificationContent> content)
    {
        if (content) {
            Parcel contentParcel;
            if (content->Marshalling(contentParcel)) {
                Notification::NotificationContent *restoredContent =
                    Notification::NotificationContent::Unmarshalling(contentParcel);
                delete restoredContent;
            }
        }
    }

    bool FuzzNotificationRequestContent(FuzzedDataProvider *fdp)
    {
        int32_t notificationId = fdp->ConsumeIntegral<int32_t>();
        Notification::NotificationRequest request(notificationId);

        uint8_t slotTypeRaw = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), SLOT_TYPE_NUM);
        request.SetSlotType(
            static_cast<Notification::NotificationConstant::SlotType>(slotTypeRaw));

        uint8_t contentSelector = ModuloByNonZero(fdp->ConsumeIntegral<uint8_t>(), CONTENT_TYPE_COUNT);

        std::string title          = fdp->ConsumeRandomLengthString(LONG_STRING_LEN);
        std::string text           = fdp->ConsumeRandomLengthString(LONG_STRING_LEN);
        std::string additionalText = fdp->ConsumeRandomLengthString(COMMON_STRING_LEN);

        std::shared_ptr<Notification::NotificationContent> content;

        if (contentSelector == CONTENT_NORMAL_INDEX) {
            content = BuildBasicTextContent(fdp, title, text, additionalText);
        } else if (contentSelector == CONTENT_MULTILINE_INDEX) {
            content = BuildLongTextContent(fdp, title, text, additionalText);
        } else {
            content = BuildMultilineContent(fdp, title, text, additionalText);
        }

        request.SetContent(content);
        request.GetContent();
        request.GetNotificationType();

        TestRequestMarshalling(request);
        TestContentMarshalling(content);

        return true;
    }
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::FuzzNotificationRequestContent(&fdp);
    return 0;
}
