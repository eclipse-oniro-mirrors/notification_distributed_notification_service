/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "notification_content.h"
#undef private
#undef protected
#include "notificationcontent_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::shared_ptr<Notification::NotificationNormalContent> normalContent =
        std::make_shared<Notification::NotificationNormalContent>();
        std::shared_ptr<Notification::NotificationLongTextContent> longTextContent =
        std::make_shared<Notification::NotificationLongTextContent>();
        std::shared_ptr<Notification::NotificationPictureContent> pictureContent =
        std::make_shared<Notification::NotificationPictureContent>();
        std::shared_ptr<Notification::NotificationConversationalContent> conversationContent =
        std::make_shared<Notification::NotificationConversationalContent>();
        std::shared_ptr<Notification::NotificationMultiLineContent> multiLineContent =
        std::make_shared<Notification::NotificationMultiLineContent>();
        std::shared_ptr<Notification::NotificationMediaContent> mediaContent =
        std::make_shared<Notification::NotificationMediaContent>();
        Notification::NotificationContent notificationContent(normalContent);
        Notification::NotificationContent notificationLongTextContent(longTextContent);
        Notification::NotificationContent notificationPictureContent(pictureContent);
        Notification::NotificationContent notificationConversationContent(conversationContent);
        Notification::NotificationContent notificationMultiLineContent(multiLineContent);
        Notification::NotificationContent notificationMediaContent(mediaContent);
        // test Dump function
        notificationContent.GetContentType();
        // test Dump function
        notificationContent.GetNotificationContent();
        // test Dump function
        notificationContent.Dump();
        // test ToJson function
        nlohmann::json jsonObject;
        notificationContent.ToJson(jsonObject);
        notificationContent.FromJson(jsonObject);
        // test Unmarshalling function
        Parcel parcel;
        notificationContent.Unmarshalling(parcel);
        notificationContent.ReadFromParcel(parcel);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    char *ch = ParseData(data, size);
    if (ch != nullptr && size >= GetU32Size()) {
        OHOS::DoSomethingInterestingWithMyAPI(ch, size);
        free(ch);
        ch = nullptr;
    }
    return 0;
}
