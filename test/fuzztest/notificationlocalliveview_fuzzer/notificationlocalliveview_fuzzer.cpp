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

#define private public
#define protected public
#include "notification_local_live_view_content.h"
#include "notification_local_live_view_button.h"
#include "notification_progress.h"
#include "notification_time.h"
#undef private
#undef protected
#include "notificationlocalliveview_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {

constexpr uint8_t LIVE_VIEW_TYPE_MAX = 4;
constexpr uint8_t FLAG_MAX = 6;

static void TestNotificationLocalLiveViewContent(FuzzedDataProvider *fuzzData)
{
    NotificationLocalLiveViewContent content;
    int32_t type = fuzzData->ConsumeIntegral<int32_t>();
    content.SetType(type);
    content.GetType();

    NotificationCapsule capsule;
    capsule.SetTitle(fuzzData->ConsumeRandomLengthString());
    content.SetCapsule(capsule);
    content.GetCapsule();

    NotificationLocalLiveViewButton button;
    button.addSingleButtonName(fuzzData->ConsumeRandomLengthString());
    content.SetButton(button);
    content.GetButton();

    NotificationProgress progress;
    progress.SetMaxValue(fuzzData->ConsumeIntegral<int32_t>());
    progress.SetCurrentValue(fuzzData->ConsumeIntegral<int32_t>());
    content.SetProgress(progress);
    content.GetProgress();

    NotificationTime time;
    time.SetInitialTime(fuzzData->ConsumeIntegral<int32_t>());
    content.SetTime(time);
    content.GetTime();

    uint8_t liveViewType = fuzzData->ConsumeIntegral<uint8_t>() % LIVE_VIEW_TYPE_MAX;
    content.SetLiveViewType(static_cast<NotificationLocalLiveViewContent::LiveViewTypes>(liveViewType));
    content.GetLiveViewType();

    int32_t flag = fuzzData->ConsumeIntegral<int32_t>() % FLAG_MAX;
    content.addFlag(flag);
    content.isFlagExist(flag);

    content.Dump();
    content.ClearButton();
    content.ClearCapsuleIcon();

    nlohmann::json jsonObject;
    content.ToJson(jsonObject);
    NotificationLocalLiveViewContent::FromJson(jsonObject);

    Parcel parcel;
    content.Marshalling(parcel);
    NotificationLocalLiveViewContent::Unmarshalling(parcel);
}

static void TestNotificationLocalLiveViewButton(FuzzedDataProvider *fuzzData)
{
    NotificationLocalLiveViewButton button;
    button.addSingleButtonName(fuzzData->ConsumeRandomLengthString());
    button.GetAllButtonNames();
    button.GetAllButtonIcons();
    button.GetAllButtonIconResource();
    button.Dump();
    button.ClearButtonIcons();
    button.ClearButtonIconsResource();

    nlohmann::json jsonObject;
    button.ToJson(jsonObject);
    NotificationLocalLiveViewButton::FromJson(jsonObject);

    Parcel parcel;
    button.Marshalling(parcel);
    NotificationLocalLiveViewButton::Unmarshalling(parcel);
}

static void TestNotificationProgress(FuzzedDataProvider *fuzzData)
{
    NotificationProgress progress;
    int32_t maxValue = fuzzData->ConsumeIntegral<int32_t>();
    int32_t currentValue = fuzzData->ConsumeIntegral<int32_t>();
    bool isPercentage = fuzzData->ConsumeBool();

    progress.SetMaxValue(maxValue);
    progress.GetMaxValue();
    progress.SetCurrentValue(currentValue);
    progress.GetCurrentValue();
    progress.SetIsPercentage(isPercentage);
    progress.GetIsPercentage();
    progress.Dump();

    nlohmann::json jsonObject;
    progress.ToJson(jsonObject);
    NotificationProgress::FromJson(jsonObject);

    Parcel parcel;
    progress.Marshalling(parcel);
    NotificationProgress::Unmarshalling(parcel);
}

static void TestNotificationTime(FuzzedDataProvider *fuzzData)
{
    NotificationTime time;
    int32_t initialTime = fuzzData->ConsumeIntegral<int32_t>();
    bool isCountDown = fuzzData->ConsumeBool();
    bool isPaused = fuzzData->ConsumeBool();
    bool isInTitle = fuzzData->ConsumeBool();

    time.SetInitialTime(initialTime);
    time.GetInitialTime();
    time.SetIsCountDown(isCountDown);
    time.GetIsCountDown();
    time.SetIsPaused(isPaused);
    time.GetIsPaused();
    time.SetIsInTitle(isInTitle);
    time.GetIsInTitle();
    time.Dump();

    nlohmann::json jsonObject;
    time.ToJson(jsonObject);
    NotificationTime::FromJson(jsonObject);

    Parcel parcel;
    time.Marshalling(parcel);
    NotificationTime::Unmarshalling(parcel);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fuzzData)
{
    TestNotificationLocalLiveViewContent(fuzzData);
    TestNotificationLocalLiveViewButton(fuzzData);
    TestNotificationProgress(fuzzData);
    TestNotificationTime(fuzzData);
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
