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

#include "notification_picture_content.h"
#include "notificationpicturecontent_fuzzer.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        std::string stringData(data);
        Notification::NotificationPictureContent notificationPictureContent;
        notificationPictureContent.SetExpandedTitle(stringData);
        notificationPictureContent.GetExpandedTitle();
        notificationPictureContent.SetBriefText(stringData);
        notificationPictureContent.GetBriefText();
        std::shared_ptr<Media::PixelMap> bigPicture = std::make_shared<Media::PixelMap>();
        notificationPictureContent.SetBigPicture(bigPicture);
        notificationPictureContent.GetBigPicture();
        notificationPictureContent.Dump();
        Parcel parcel;
        return notificationPictureContent.Marshalling(parcel);
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
