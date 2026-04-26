/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define private public  // NOLINT
#define protected public  // NOLINT
#include "notification_capsule.h"
#include "notification_icon_button.h"
#undef private
#undef protected
#include "notificationcapsule_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

constexpr uint8_t MAX_BUTTON_SIZE = 3;

static void TestNotificationCapsule(FuzzedDataProvider *fuzzData)
{
    NotificationCapsule capsule;
    std::string title = fuzzData->ConsumeRandomLengthString();
    std::string backgroundColor = fuzzData->ConsumeRandomLengthString();
    std::string content = fuzzData->ConsumeRandomLengthString();
    int32_t time = fuzzData->ConsumeIntegral<int32_t>();

    capsule.SetTitle(title);
    capsule.GetTitle();
    capsule.SetBackgroundColor(backgroundColor);
    capsule.GetBackgroundColor();
    capsule.SetContent(content);
    capsule.GetContent();
    capsule.SetTime(time);
    capsule.GetTime();
    capsule.Dump();
    capsule.ResetIcon();

    nlohmann::json jsonObject;
    capsule.ToJson(jsonObject);
    NotificationCapsule::FromJson(jsonObject);

    Parcel parcel;
    capsule.Marshalling(parcel);
    NotificationCapsule::Unmarshalling(parcel);
}

static void TestNotificationIconButton(FuzzedDataProvider *fuzzData)
{
    NotificationIconButton button;
    std::string text = fuzzData->ConsumeRandomLengthString();
    std::string name = fuzzData->ConsumeRandomLengthString();
    bool hidePanel = fuzzData->ConsumeBool();

    button.SetText(text);
    button.GetText();
    button.SetName(name);
    button.GetName();
    button.SetHidePanel(hidePanel);
    button.GetHidePanel();
    button.Dump();
    button.ClearButtonIconsResource();

    nlohmann::json jsonObject;
    button.ToJson(jsonObject);
    NotificationIconButton::FromJson(jsonObject);

    Parcel parcel;
    button.Marshalling(parcel);
    NotificationIconButton::Unmarshalling(parcel);
}

static void TestNotificationIconButtonWithResource(FuzzedDataProvider *fuzzData)
{
    NotificationIconButton button;
    std::string text = fuzzData->ConsumeRandomLengthString();
    button.SetText(text);
    Parcel writeParcel;
    button.WriteIconToParcel(writeParcel);

    Parcel readParcel;
    std::shared_ptr<ResourceManager::Resource> resourceObj;
    button.ReadResourceFromParcel(readParcel, resourceObj);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationCapsule(fuzzData);
    TestNotificationIconButton(fuzzData);
    TestNotificationIconButtonWithResource(fuzzData);
    return true;
}
}  // namespace Notification
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fuzzData(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fuzzData);
    return 0;
}
