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
#include "notification_capsule.h"
#include "notification_disable.h"
#include "notification_do_not_disturb_profile.h"
#include "notification_icon_button.h"
#include "notification_live_view_content.h"
#include "notification_local_live_view_button.h"
#include "notification_local_live_view_content.h"
#include "notification_operation_info.h"
#include "notification_unified_group_Info.h"
#include "resource_manager.h"
#include "notificationparcel_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Notification {
    void TestNotificationCapsuleParcel(FuzzedDataProvider *fdp)
    {
        NotificationCapsule capsule;
        Parcel parcel;
        nlohmann::json jsonObject;
        std::string stringData = fdp->ConsumeRandomLengthString();
        int32_t time = fdp->ConsumeIntegral<int32_t>();

        capsule.SetTitle(stringData);
        capsule.GetTitle();
        capsule.SetBackgroundColor(stringData);
        capsule.GetBackgroundColor();
        capsule.SetContent(stringData);
        capsule.GetContent();
        capsule.SetTime(time);
        capsule.GetTime();
        capsule.ToJson(jsonObject);
        capsule.Dump();
        capsule.FromJson(jsonObject);
        capsule.Marshalling(parcel);
        capsule.Unmarshalling(parcel);
    }

    void TestNotificationDoNotDisturbProfileParcel(FuzzedDataProvider *fdp)
    {
        NotificationDoNotDisturbProfile disturbProfile;
        Parcel parcel;
        int64_t profileId = fdp->ConsumeIntegral<int64_t>();
        std::string profileName = fdp->ConsumeRandomLengthString();
        std::vector<NotificationBundleOption> trustList;
        NotificationBundleOption bundleOption;
        trustList.push_back(bundleOption);

        disturbProfile.SetProfileId(profileId);
        disturbProfile.GetProfileId();
        disturbProfile.SetProfileName(profileName);
        disturbProfile.GetProfileName();
        disturbProfile.SetProfileTrustList(trustList);
        disturbProfile.GetProfileTrustList();
        disturbProfile.Marshalling(parcel);
        disturbProfile.ReadFromParcel(parcel);
        disturbProfile.Unmarshalling(parcel);
        std::string disturbProfileJson = disturbProfile.ToJson();
        disturbProfile.FromJson(disturbProfileJson);
    }

    void TestNotificationDisableParcel(FuzzedDataProvider *fdp)
    {
        NotificationDisable notificationDisable;
        std::vector<std::string> bundleList;
        bool disabled = fdp->ConsumeBool();
        Parcel parcel;
    
        bundleList.emplace_back(fdp->ConsumeRandomLengthString());
        notificationDisable.SetDisabled(disabled);
        notificationDisable.GetDisabled();
        notificationDisable.SetBundleList(bundleList);
        notificationDisable.GetBundleList();
    
        notificationDisable.Marshalling(parcel);
        notificationDisable.ReadFromParcel(parcel);
        notificationDisable.Unmarshalling(parcel);
    
        std::string jsonObj = notificationDisable.ToJson();
        notificationDisable.FromJson(jsonObj);
    }

    void TestNotificationLiveViewContentParcel(FuzzedDataProvider *fdp)
    {
        NotificationLiveViewContent liveViewContent;
        PictureMap picMap;
        nlohmann::json jsonObject;
        auto extraInfo = std::make_shared<AAFwk::WantParams>();
    
        liveViewContent.SetVersion(fdp->ConsumeIntegral<uint32_t>());
        liveViewContent.GetVersion();
        liveViewContent.SetText(fdp->ConsumeRandomLengthString());
        liveViewContent.SetTitle(fdp->ConsumeRandomLengthString());
        liveViewContent.SetAdditionalText(fdp->ConsumeRandomLengthString());
        liveViewContent.SetIsOnlyLocalUpdate(fdp->ConsumeBool());
        liveViewContent.SetPicture(picMap);
        liveViewContent.SetExtraInfo(extraInfo);
        liveViewContent.Dump();
        liveViewContent.ToJson(jsonObject);
        liveViewContent.FromJson(jsonObject);
    }

    void TestNotificationLocalLiveViewButtonParcel(FuzzedDataProvider *fdp)
    {
        NotificationLocalLiveViewButton button;
        std::string buttonName = fdp->ConsumeRandomLengthString();
        auto pixelMapOne = std::make_shared<Media::PixelMap>();
        auto pixelMapTwo = std::make_shared<Media::PixelMap>();
        auto iconResource = std::make_shared<ResourceManager::Resource>();
        iconResource->id = fdp->ConsumeIntegral<int32_t>();
        iconResource->bundleName = fdp->ConsumeRandomLengthString();
        iconResource->moduleName = fdp->ConsumeRandomLengthString();
        Parcel parcel;
        nlohmann::json jsonObj;

        button.addSingleButtonName(buttonName);
        button.GetAllButtonNames();
        button.addSingleButtonIcon(pixelMapOne);
        button.addSingleButtonIcon(pixelMapTwo);
        button.GetAllButtonIcons();
        button.addSingleButtonIconResource(iconResource);
        button.GetAllButtonIconResource();
        button.Dump();
    
        button.ToJson(jsonObj);
        button.FromJson(jsonObj);

        button.Marshalling(parcel);
        button.Unmarshalling(parcel);
        button.ClearButtonIcons();
        button.ClearButtonIconsResource();
    }

    void TestNotificationLocalLiveViewContentParcel(FuzzedDataProvider *fdp)
    {
        NotificationLocalLiveViewContent content;
        NotificationCapsule capsule;
        NotificationLocalLiveViewButton button;
        NotificationIconButton iconButton;
        std::vector<NotificationIconButton> iconButtons;
        NotificationProgress progress;
        NotificationTime time;
        Parcel parcel;
        nlohmann::json jsonObj;
        int32_t flag = fdp->ConsumeIntegral<int32_t>();
        iconButtons.push_back(iconButton);
        content.SetType(fdp->ConsumeIntegral<int32_t>());
        content.GetType();
        content.SetCapsule(capsule);
        content.GetCapsule();
        content.SetButton(button);
        content.GetButton();
        content.SetCardButton(iconButtons);
        content.GetCardButton();
        content.SetProgress(progress);
        content.GetProgress();
        content.SetTime(time);
        content.GetTime();
        content.addFlag(flag);
        content.isFlagExist(flag);
        content.isFlagExist(fdp->ConsumeIntegral<int32_t>());
        content.Dump();

        content.ToJson(jsonObj);
        content.FromJson(jsonObj);

        content.Marshalling(parcel);
        content.Unmarshalling(parcel);

        content.ClearButton();
        content.ClearCapsuleIcon();
    }

    void TestNotificationOperationInfoParcel(FuzzedDataProvider *fdp)
    {
        NotificationOperationInfo info;
        std::string actionName = fdp->ConsumeRandomLengthString();
        std::string userInput = fdp->ConsumeRandomLengthString();
        std::string hashCode = fdp->ConsumeRandomLengthString();
        std::string eventId = fdp->ConsumeRandomLengthString();
        Parcel parcel;

        info.SetActionName(actionName);
        info.GetActionName();
        info.SetUserInput(userInput);
        info.GetUserInput();
        info.SetHashCode(hashCode);
        info.GetHashCode();
        info.SetEventId(eventId);
        info.GetEventId();
        info.Dump();
        info.Marshalling(parcel);
        info.Unmarshalling(parcel);
    }

    void TestNotificationUnifiedGroupInfoParcel(FuzzedDataProvider *fdp)
    {
        NotificationUnifiedGroupInfo info;
        std::string key = fdp->ConsumeRandomLengthString();
        std::string title = fdp->ConsumeRandomLengthString();
        std::string content = fdp->ConsumeRandomLengthString();
        std::string sceneName = fdp->ConsumeRandomLengthString();
        auto extraInfo = std::make_shared<AAFwk::WantParams>();
        Parcel parcel;
    
        info.SetKey(key);
        info.GetKey();
        info.SetTitle(title);
        info.GetTitle();
        info.SetContent(content);
        info.GetContent();
        info.SetSceneName(sceneName);
        info.GetSceneName();
        info.SetExtraInfo(extraInfo);
        info.GetExtraInfo();
        info.Dump();
        info.Marshalling(parcel);
        info.Unmarshalling(parcel);
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        TestNotificationCapsuleParcel(fdp);
        TestNotificationDoNotDisturbProfileParcel(fdp);
        TestNotificationDisableParcel(fdp);
        TestNotificationLiveViewContentParcel(fdp);
        TestNotificationLocalLiveViewButtonParcel(fdp);
        TestNotificationLocalLiveViewContentParcel(fdp);
        TestNotificationOperationInfoParcel(fdp);
        TestNotificationUnifiedGroupInfoParcel(fdp);
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
